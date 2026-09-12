// Tests assert invariants directly; unwraps keep failures loud.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

//! Config-knob behavior matrix: every public `JwtConfig` builder and JWKS
//! cache knob must observably change behavior. Deterministic: no sleeps,
//! no external network (JWKS tests run against a loopback mock).

use serde::{Deserialize, Serialize};
use tokenkit::claims::StandardClaims;
use tokenkit::service::{JwtAlgorithm, JwtConfig, JwtService};

#[derive(Debug, Serialize, Deserialize)]
struct TtlClaims {
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
}

/// Fresh (unstamped) claims: `encode_standard` / `encode_refresh_standard`
/// fill in `exp` from the configured TTL.
fn fresh_claims() -> StandardClaims {
    StandardClaims {
        sub: Some("user-1".to_string()),
        ..Default::default()
    }
}

fn now_secs() -> u64 {
    chrono::Utc::now().timestamp() as u64
}

fn mint_service(ttl_field: &str, ttl: i64) -> JwtService {
    let mut config = JwtConfig {
        algorithm: JwtAlgorithm::HS256,
        secret: format!("config-matrix-{ttl_field}-secret"),
        issuer: Some("config-matrix-issuer".to_string()),
        ..Default::default()
    };
    if ttl_field == "access" {
        config.access_token_ttl = ttl;
    } else {
        config.refresh_token_ttl = ttl;
    }
    JwtService::new(config)
}

/// `access_token_ttl` stamps `exp` ≈ now + access TTL on minted access
/// tokens (claims without an explicit `exp`).
#[test]
fn access_token_ttl_controls_minted_expiry() {
    let service = mint_service("access", 120);
    let token = service.encode_standard(fresh_claims()).unwrap();
    let decoded: TtlClaims = service.decode(&token).unwrap();
    let exp = decoded.exp.expect("encode_standard must stamp exp");
    let now = now_secs();
    assert!(
        (now + 115..=now + 120).contains(&exp),
        "exp {exp} must be ~now+120 (access ttl)"
    );
}

/// `refresh_token_ttl` is wired through `encode_refresh_standard`: it stamps
/// the refresh TTL, not the access TTL — the two knobs are independently
/// observable on the same service.
#[test]
fn refresh_token_ttl_controls_refresh_expiry_and_differs_from_access() {
    // Default refresh TTL is 7 days; access TTL is 1 hour.
    let config = JwtConfig {
        secret: "config-matrix-refresh-default-secret".to_string(),
        issuer: Some("config-matrix-issuer".to_string()),
        ..Default::default()
    };
    let service = JwtService::new(config);
    let claims = fresh_claims();

    let access = service.encode_standard(claims.clone()).unwrap();
    let refresh = service.encode_refresh_standard(claims).unwrap();

    let access_exp: u64 = service
        .decode::<TtlClaims>(&access)
        .unwrap()
        .exp
        .expect("access exp");
    let refresh_exp: u64 = service
        .decode::<TtlClaims>(&refresh)
        .unwrap()
        .exp
        .expect("refresh exp");

    let now = now_secs();
    assert!(
        (now + 3540..=now + 3600).contains(&access_exp),
        "access exp {access_exp} must be ~now+3600"
    );
    assert!(
        (now + 604_780..=now + 604_800).contains(&refresh_exp),
        "refresh exp {refresh_exp} must be ~now+604800"
    );
    assert!(
        refresh_exp - access_exp > 600_000,
        "refresh token must outlive the access token by days, not seconds"
    );

    // A custom refresh TTL is honored exactly.
    let service = mint_service("refresh", 90);
    let token = service
        .encode_refresh_standard(StandardClaims {
            sub: Some("user-2".to_string()),
            ..Default::default()
        })
        .unwrap();
    let decoded: TtlClaims = service.decode(&token).unwrap();
    let exp = decoded.exp.expect("refresh exp");
    let now = now_secs();
    assert!(
        (now + 85..=now + 90).contains(&exp),
        "exp {exp} must be ~now+90 (refresh ttl)"
    );
}

/// `with_audiences`: a token whose `aud` is in the accepted set validates;
/// the same token is rejected when the set does not contain it.
#[test]
fn with_audiences_accepts_listed_and_rejects_unlisted() {
    let claims = TtlClaims {
        sub: Some("user-1".to_string()),
        exp: Some(now_secs() + 3600),
        iss: Some("config-matrix-issuer".to_string()),
        aud: Some("aud-b".to_string()),
    };

    let accepting = JwtService::new(
        JwtConfig {
            secret: "config-matrix-audiences-secret".to_string(),
            issuer: Some("config-matrix-issuer".to_string()),
            ..Default::default()
        }
        .with_audiences(vec!["aud-a".to_string(), "aud-b".to_string()]),
    );
    let ok: TtlClaims = accepting
        .decode(&accepting.encode(&claims).unwrap())
        .unwrap();
    assert_eq!(ok.aud.as_deref(), Some("aud-b"));

    let rejecting = JwtService::new(
        JwtConfig {
            secret: "config-matrix-audiences-secret".to_string(),
            issuer: Some("config-matrix-issuer".to_string()),
            ..Default::default()
        }
        .with_audiences(vec!["aud-a".to_string()]),
    );
    assert!(
        rejecting
            .decode::<TtlClaims>(&rejecting.encode(&claims).unwrap())
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// JWKS knobs (feature "jwks"): with_client, with_min_refresh_interval,
// with_ttl — behavior proven against a loopback mock that counts fetches.
// ---------------------------------------------------------------------------
#[cfg(feature = "jwks")]
mod jwks_config_tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokenkit::jwks::JwksCache;

    /// HMAC key: base64url(no pad) of "secret" is "c2VjcmV0". Test-only.
    const JWKS_BODY: &str = r#"{"keys":[{"kty":"oct","k":"c2VjcmV0","kid":"k1","alg":"HS256"}]}"#;

    struct MockJwks {
        url: String,
        fetches: Arc<AtomicUsize>,
        last_request: Arc<std::sync::Mutex<String>>,
    }

    /// Serve `max_requests` sequential JWKS responses on an ephemeral
    /// loopback port, recording the fetch count and last raw request.
    fn spawn_mock_jwks(max_requests: usize) -> MockJwks {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let fetches = Arc::new(AtomicUsize::new(0));
        let last_request = Arc::new(std::sync::Mutex::new(String::new()));

        let f = Arc::clone(&fetches);
        let lr = Arc::clone(&last_request);
        std::thread::spawn(move || {
            for stream in listener.incoming().take(max_requests) {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                if let Ok(req) = std::str::from_utf8(&buf[..n]) {
                    *lr.lock().unwrap() = req.to_ascii_lowercase();
                }
                f.fetch_add(1, Ordering::SeqCst);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    JWKS_BODY.len(),
                    JWKS_BODY
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        MockJwks {
            url: format!("http://127.0.0.1:{port}/jwks.json"),
            fetches,
            last_request,
        }
    }

    fn hs256_token(kid: &str) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(kid.to_string());
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({"sub": "u1", "exp": chrono::Utc::now().timestamp() as u64 + 3600}),
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .unwrap()
    }

    fn validation() -> jsonwebtoken::Validation {
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        v.required_spec_claims.clear();
        v
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    /// `with_client` must route JWKS fetches through the provided client.
    /// The custom client stamps a probe header; the mock observes it on the
    /// wire — the default client would never send it.
    #[test]
    fn with_client_routes_fetches_through_provided_client() {
        let mock = spawn_mock_jwks(4);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-probe",
            reqwest::header::HeaderValue::from_static("config-matrix"),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap();

        let cache = JwksCache::new(mock.url.clone())
            .with_client(client)
            .with_min_refresh_interval(Duration::ZERO);

        let rt = runtime();
        rt.block_on(async {
            let claims: serde_json::Value = cache
                .decode(&hs256_token("k1"), &validation())
                .await
                .unwrap();
            assert_eq!(claims["sub"], "u1");
        });

        assert!(
            mock.fetches.load(Ordering::SeqCst) >= 1,
            "a fetch must have happened"
        );
        let req = mock.last_request.lock().unwrap();
        assert!(
            req.contains("x-probe: config-matrix"),
            "fetch must carry the custom client's probe header, got: {req}"
        );
    }

    /// `with_min_refresh_interval` (default 10s): within the window after a
    /// fetch, on-miss refreshes are SKIPPED (no second fetch). With the
    /// interval at ZERO the very same miss DOES re-fetch — the knob
    /// observably changes refresh behavior.
    #[test]
    fn min_refresh_interval_skips_on_miss_refreshes_within_window() {
        // Default interval: second (unknown-kid) lookup must not re-fetch.
        let mock = spawn_mock_jwks(4);
        let cache = JwksCache::new(mock.url.clone()); // default 10s interval
        let rt = runtime();
        rt.block_on(async {
            let claims: serde_json::Value = cache
                .decode(&hs256_token("k1"), &validation())
                .await
                .unwrap();
            assert_eq!(claims["sub"], "u1");
            assert_eq!(mock.fetches.load(Ordering::SeqCst), 1);

            // Unknown kid, but still inside the min-refresh window: no new
            // fetch — the error must come from the post-skip lookup.
            let err = cache
                .decoding_key(Some("k2"))
                .await
                .expect_err("unknown kid must fail");
            assert!(matches!(err, tokenkit::error::JwtError::Jwks(_)), "{err:?}");
        });
        assert_eq!(
            mock.fetches.load(Ordering::SeqCst),
            1,
            "refresh within the min interval must be skipped"
        );

        // Same miss with a ZERO interval: the refresh must actually happen.
        let mock = spawn_mock_jwks(4);
        let cache = JwksCache::new(mock.url.clone()).with_min_refresh_interval(Duration::ZERO);
        rt.block_on(async {
            let claims: serde_json::Value = cache
                .decode(&hs256_token("k1"), &validation())
                .await
                .unwrap();
            assert_eq!(claims["sub"], "u1");
            let err = cache
                .decoding_key(Some("k2"))
                .await
                .expect_err("unknown kid must fail");
            assert!(matches!(err, tokenkit::error::JwtError::Jwks(_)), "{err:?}");
        });
        assert_eq!(
            mock.fetches.load(Ordering::SeqCst),
            2,
            "ZERO min interval must allow the on-miss refresh"
        );
    }

    /// `with_ttl(ZERO)`: every lookup is stale, so even a cached kid
    /// triggers a re-fetch (rate-limit disabled) — versus the default TTL,
    /// where a second decode of the same kid never fetches.
    #[test]
    fn zero_ttl_refetches_even_cached_kids() {
        let mock = spawn_mock_jwks(4);
        let cache = JwksCache::new(mock.url.clone())
            .with_ttl(Duration::ZERO)
            .with_min_refresh_interval(Duration::ZERO);
        let rt = runtime();
        rt.block_on(async {
            for _ in 0..2 {
                let claims: serde_json::Value = cache
                    .decode(&hs256_token("k1"), &validation())
                    .await
                    .unwrap();
                assert_eq!(claims["sub"], "u1");
            }
        });
        assert_eq!(
            mock.fetches.load(Ordering::SeqCst),
            2,
            "zero TTL must force a refresh on every lookup"
        );
    }
}
