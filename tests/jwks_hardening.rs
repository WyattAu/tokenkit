// JWKS hardening: single-flight refresh coalescing, minimum refresh
// interval, static key sets, and algorithm pinning (alg-confusion).
//
// A tiny hand-rolled HTTP server (std TcpListener) serves canned JWKS
// bodies and counts requests — proving how many fetches the cache made.
//
// unwrap/expect are the test signal here.
#![cfg(feature = "jwks")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, encode};
use tokenkit::error::JwtError;
use tokenkit::jwks::JwksCache;

/// Secret for the HMAC JWKS tests: base64url("aa") == "YWE" (no +/ chars,
/// so standard base64 equals base64url here).
const OCT_SECRET: &[u8] = b"aa";

struct SpyServer {
    url: String,
    hits: Arc<AtomicUsize>,
}

/// Serve `body` (a JWKS document) forever; count accepted connections.
fn spawn_jwks_server(body: &'static str) -> SpyServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_thread = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            hits_thread.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    SpyServer {
        url: format!("http://{addr}/jwks.json"),
        hits,
    }
}

fn hits(server: &SpyServer) -> usize {
    server.hits.load(Ordering::SeqCst)
}

fn hs256_token(kid: Option<&str>) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = kid.map(str::to_string);
    encode(
        &header,
        &serde_json::json!({"sub": "user-1", "exp": 4102444800u64}),
        &EncodingKey::from_secret(OCT_SECRET),
    )
    .unwrap()
}

fn hs256_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

/// N concurrent unknown-kid lookups must coalesce into exactly ONE fetch.
#[test]
fn concurrent_misses_trigger_single_fetch() {
    let server =
        spawn_jwks_server(r#"{"keys": [{"kty": "oct", "k": "YWE", "kid": "k1", "alg": "HS256"}]}"#);
    let cache = Arc::new(JwksCache::new(&server.url));
    let rt = runtime();
    rt.block_on(async {
        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache
                    .decoding_key(Some("missing-kid"))
                    .await
                    .expect_err("kid is absent from the served set")
            }));
        }
        for handle in handles {
            let err = handle.await.unwrap();
            assert!(matches!(err, JwtError::Jwks(_)), "{err:?}");
        }
    });
    assert_eq!(hits(&server), 1, "concurrent misses must share one fetch");
}

/// Within the min-refresh interval, a stale-TTL cache is served without a
/// re-fetch (herd protection), even though the TTL has expired.
#[test]
fn min_refresh_interval_skips_refetch() {
    let server =
        spawn_jwks_server(r#"{"keys": [{"kty": "oct", "k": "YWE", "kid": "k1", "alg": "HS256"}]}"#);
    let cache = JwksCache::new(&server.url).with_ttl(Duration::ZERO);
    let rt = runtime();
    rt.block_on(async {
        // First lookup fetches.
        cache.decoding_key(Some("k1")).await.unwrap();
        assert_eq!(hits(&server), 1);

        // Second lookup: cache is stale (ttl zero) but the last fetch is
        // younger than the default 10s min-refresh interval — skip.
        cache.decoding_key(Some("k1")).await.unwrap();
        assert_eq!(hits(&server), 1, "min refresh interval must skip refetch");
    });
}

/// `with_min_refresh_interval(Duration::ZERO)` restores refresh on every
/// stale/miss lookup.
#[test]
fn zero_min_refresh_interval_allows_immediate_refetch() {
    let server =
        spawn_jwks_server(r#"{"keys": [{"kty": "oct", "k": "YWE", "kid": "k1", "alg": "HS256"}]}"#);
    let cache = JwksCache::new(&server.url)
        .with_ttl(Duration::ZERO)
        .with_min_refresh_interval(Duration::ZERO);
    let rt = runtime();
    rt.block_on(async {
        cache.decoding_key(Some("k1")).await.unwrap();
        cache.decoding_key(Some("k1")).await.unwrap();
        assert_eq!(hits(&server), 2, "zero interval must allow both fetches");
    });
}

/// Air-gapped mode: `from_static_keys` decodes without any network.
#[test]
fn static_keys_roundtrip_without_network() {
    let mut keys = HashMap::new();
    keys.insert(
        "static-kid".to_string(),
        DecodingKey::from_secret(b"static-jwks-secret"),
    );
    let cache = JwksCache::from_static_keys(keys);
    let rt = runtime();
    rt.block_on(async {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("static-kid".to_string());
        let token = encode(
            &header,
            &serde_json::json!({"sub": "static-user"}),
            &EncodingKey::from_secret(b"static-jwks-secret"),
        )
        .unwrap();
        let claims: serde_json::Value = cache.decode(&token, &hs256_validation()).await.unwrap();
        assert_eq!(claims["sub"], "static-user");
    });
}

/// A JWK advertising `alg: RS256` must NOT accept a token whose header
/// claims HS256 — the alg-confusion defense.
#[test]
fn jwk_alg_pinned_rejects_mismatched_token_alg() {
    let server = spawn_jwks_server(
        // Key material is an HMAC secret, but the JWK *claims* RS256 —
        // exactly the confusion an attacker would engineer.
        r#"{"keys": [{"kty": "oct", "k": "YWE", "kid": "k1", "alg": "RS256"}]}"#,
    );
    let cache = JwksCache::new(&server.url);
    let rt = runtime();
    rt.block_on(async {
        let token = hs256_token(Some("k1"));
        let err = cache
            .decode::<serde_json::Value>(&token, &hs256_validation())
            .await
            .expect_err("HS256 token must not verify against an RS256-pinned key");
        assert!(
            matches!(&err, JwtError::AlgorithmMismatch { token_alg, key_alg }
                if token_alg == "HS256" && key_alg == "RS256"),
            "{err:?}"
        );
    });
}

/// When the JWK's `alg` matches the token header, decoding proceeds.
#[test]
fn jwk_alg_match_accepted() {
    let server =
        spawn_jwks_server(r#"{"keys": [{"kty": "oct", "k": "YWE", "kid": "k1", "alg": "HS256"}]}"#);
    let cache = JwksCache::new(&server.url);
    let rt = runtime();
    rt.block_on(async {
        let token = hs256_token(Some("k1"));
        let claims: serde_json::Value = cache
            .decode(&token, &hs256_validation())
            .await
            .expect("matching algs must verify");
        assert_eq!(claims["sub"], "user-1");
    });
}

/// A JWK without `alg` accepts only the caller's configured algorithm —
/// enforced by jsonwebtoken against `Validation`.
#[test]
fn jwk_without_alg_requires_validation_algorithm() {
    let server = spawn_jwks_server(r#"{"keys": [{"kty": "oct", "k": "YWE", "kid": "k1"}]}"#);
    let cache = JwksCache::new(&server.url);
    let rt = runtime();
    rt.block_on(async {
        let token = hs256_token(Some("k1"));

        // Caller configured ES384: the HS256 header is rejected.
        let mut es384_validation = Validation::new(Algorithm::ES384);
        es384_validation.required_spec_claims.clear();
        assert!(
            cache
                .decode::<serde_json::Value>(&token, &es384_validation)
                .await
                .is_err(),
            "token alg outside Validation must fail"
        );

        // Caller configured HS256 (matching the header): accepted.
        let claims: serde_json::Value = cache
            .decode(&token, &hs256_validation())
            .await
            .expect("validation alg matching the header must verify");
        assert_eq!(claims["sub"], "user-1");
    });
}
