//! JWKS fetching and caching with automatic rotation on `kid` miss.
//!
//! Enabled with the `jwks` feature. [`JwksCache`] fetches a JSON Web Key Set
//! from a URL, caches the decoded keys for a configurable TTL, and re-fetches
//! whenever a token references an unknown `kid` — so rotated keys are picked
//! up without restarts or redeploys.
//!
//! # Example
//!
//! ```no_run
//! use jsonwebtoken::{Algorithm, Validation};
//! use tokenkit::jwks::JwksCache;
//!
//! # async fn example() -> Result<(), tokenkit::error::JwtError> {
//! let cache = JwksCache::new("https://issuer.example.com/.well-known/jwks.json");
//! let mut validation = Validation::new(Algorithm::RS256);
//! validation.set_required_spec_claims(&["exp", "iss"]);
//! let claims: serde_json::Value = cache.decode("header.payload.signature", &validation).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use tokio::sync::RwLock;

use crate::error::JwtError;

/// Default cache TTL: 10 minutes.
const DEFAULT_TTL: Duration = Duration::from_secs(600);

struct CachedKeys {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
}

/// A cached JWKS key set fetched from a remote URL.
///
/// Keys are cached for [`JwksCache::with_ttl`] (10 minutes by default). A
/// lookup for an unknown `kid`, or an expired cache, triggers a re-fetch —
/// this is the rotation path: newly published keys are picked up on first
/// use, without restarts.
pub struct JwksCache {
    url: String,
    ttl: Duration,
    client: reqwest::Client,
    state: RwLock<CachedKeys>,
}

impl JwksCache {
    /// Create a cache that fetches the JWKS from `url` with the default TTL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ttl: DEFAULT_TTL,
            client: reqwest::Client::new(),
            state: RwLock::new(CachedKeys {
                keys: HashMap::new(),
                fetched_at: None,
            }),
        }
    }

    /// Set the cache TTL (how long a fetched set is served without re-fetch).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Use a custom `reqwest` client (e.g. with extra TLS or proxy config).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Re-fetch the JWKS from the configured URL, replacing the cache.
    ///
    /// Keys that cannot be converted to a [`DecodingKey`] (e.g. exotic key
    /// types the backend does not support) are skipped; if no usable keys
    /// remain, an error is returned and the previous cache is kept.
    pub async fn refresh(&self) -> Result<(), JwtError> {
        let response = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| JwtError::Jwks(format!("fetch failed for {}: {e}", self.url)))?;

        let response = response
            .error_for_status()
            .map_err(|e| JwtError::Jwks(format!("JWKS endpoint returned an error: {e}")))?;

        let set: JwkSet = response
            .json()
            .await
            .map_err(|e| JwtError::Jwks(format!("invalid JWKS document: {e}")))?;

        let keys = build_key_map(&set)?;
        let mut state = self.state.write().await;
        state.keys = keys;
        state.fetched_at = Some(Instant::now());
        Ok(())
    }

    /// Resolve the [`DecodingKey`] for `kid`.
    ///
    /// Serves a fresh cache hit directly. On an unknown `kid` — or a stale
    /// cache — the JWKS is re-fetched once (rotation) before giving up.
    pub async fn decoding_key(&self, kid: Option<&str>) -> Result<DecodingKey, JwtError> {
        let want = kid.unwrap_or_default();

        {
            let state = self.state.read().await;
            if is_fresh(state.fetched_at, self.ttl)
                && let Some(key) = state.keys.get(want)
            {
                return Ok(key.clone());
            }
        }

        // Slow path: stale cache or kid-miss (key rotation) — re-fetch, then
        // look up once more.
        self.refresh().await?;

        let state = self.state.read().await;
        state
            .keys
            .get(want)
            .cloned()
            .ok_or_else(|| JwtError::Jwks(format!("unknown key id `{want}` after JWKS refresh")))
    }

    /// Decode `token` with the JWKS key referenced by its `kid` header.
    ///
    /// The `kid` is read from the token header (unverified), the matching
    /// key is resolved via [`JwksCache::decoding_key`] (refreshing on
    /// rotation), and the token is verified against `validation`.
    pub async fn decode<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> Result<T, JwtError> {
        let header = decode_header(token).map_err(|e| JwtError::DecodingFailed(e.to_string()))?;
        let key = self.decoding_key(header.kid.as_deref()).await?;
        decode::<T>(token, &key, validation)
            .map(|data| data.claims)
            .map_err(|e| JwtError::DecodingFailed(e.to_string()))
    }
}

fn is_fresh(fetched_at: Option<Instant>, ttl: Duration) -> bool {
    fetched_at.is_some_and(|at| at.elapsed() < ttl)
}

/// Convert a [`JwkSet`] into a `kid` → [`DecodingKey`] map.
///
/// Keys without a `kid` are stored under the empty string so single-key sets
/// still resolve for tokens that carry no `kid` header. Unconvertible keys
/// are skipped; an error is returned only when nothing usable remains.
fn build_key_map(set: &JwkSet) -> Result<HashMap<String, DecodingKey>, JwtError> {
    let mut keys = HashMap::new();
    for jwk in &set.keys {
        let kid = jwk.common.key_id.clone().unwrap_or_default();
        if let Ok(key) = DecodingKey::from_jwk(jwk) {
            keys.insert(kid, key);
        }
    }
    if keys.is_empty() {
        return Err(JwtError::Jwks(
            "JWKS document contained no usable keys".to_string(),
        ));
    }
    Ok(keys)
}

// Tests drive async code through a manually built runtime: this crate's
// tokio dependency has no "macros" feature, so `#[tokio::test]` is
// unavailable. Network-dependent paths use an unroutable loopback URL, which
// fails fast and proves whether a fetch was attempted.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// An endpoint that refuses connections immediately: any attempted fetch
    /// fails fast. Success against this URL proves no fetch was attempted.
    const UNROUTABLE_URL: &str = "http://127.0.0.1:1/jwks.json";

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    fn cache_with_key(kid: &str) -> JwksCache {
        let cache = JwksCache::new(UNROUTABLE_URL);
        let rt = runtime();
        rt.block_on(async {
            let mut state = cache.state.write().await;
            state.keys.insert(
                kid.to_string(),
                DecodingKey::from_secret(b"test-secret-for-jwks-cache"),
            );
            state.fetched_at = Some(Instant::now());
        });
        cache
    }

    #[test]
    fn cache_hit_serves_without_fetch() {
        let cache = cache_with_key("key-1");
        let rt = runtime();
        rt.block_on(async {
            // Succeeds despite the unroutable URL: no fetch was attempted.
            let key = cache.decoding_key(Some("key-1")).await.unwrap();
            // Round-trip through the key to prove it is the cached one.
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
            header.kid = Some("key-1".to_string());
            let token = jsonwebtoken::encode(
                &header,
                &serde_json::json!({"sub": "u1"}),
                &jsonwebtoken::EncodingKey::from_secret(b"test-secret-for-jwks-cache"),
            )
            .unwrap();
            let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
            validation.required_spec_claims.clear();
            let data: serde_json::Value = cache.decode(&token, &validation).await.unwrap();
            assert_eq!(data["sub"], "u1");
            let _ = key;
        });
    }

    #[test]
    fn kid_miss_triggers_refresh_and_fails_closed() {
        let cache = cache_with_key("key-1");
        let rt = runtime();
        rt.block_on(async {
            // "key-2" is not cached: the cache must attempt a refresh (which
            // fails against the unroutable URL) rather than fail silently.
            let err = cache.decoding_key(Some("key-2")).await.unwrap_err();
            assert!(matches!(err, JwtError::Jwks(_)), "{err:?}");
        });
    }

    #[test]
    fn empty_cache_fetch_failure_is_an_error() {
        let cache = JwksCache::new(UNROUTABLE_URL);
        let rt = runtime();
        rt.block_on(async {
            let err = cache.decoding_key(Some("any")).await.unwrap_err();
            assert!(matches!(err, JwtError::Jwks(_)), "{err:?}");
            let err = cache.refresh().await.unwrap_err();
            assert!(matches!(err, JwtError::Jwks(_)), "{err:?}");
        });
    }

    #[test]
    fn stale_cache_triggers_refresh() {
        let cache = JwksCache::new(UNROUTABLE_URL).with_ttl(Duration::ZERO);
        let rt = runtime();
        rt.block_on(async {
            {
                let mut state = cache.state.write().await;
                state.keys.insert(
                    "key-1".to_string(),
                    DecodingKey::from_secret(b"test-secret-for-jwks-cache"),
                );
                state.fetched_at = Some(Instant::now());
            }
            // TTL of zero means every lookup is stale: a refresh is attempted
            // even for a cached kid, and fails against the unroutable URL.
            let err = cache.decoding_key(Some("key-1")).await.unwrap_err();
            assert!(matches!(err, JwtError::Jwks(_)), "{err:?}");
        });
    }

    #[test]
    fn build_key_map_rejects_unusable_sets() {
        let set: JwkSet = serde_json::from_str(r#"{"keys": []}"#).unwrap();
        let err = build_key_map(&set).unwrap_err();
        assert!(matches!(err, JwtError::Jwks(_)), "{err:?}");
    }

    #[test]
    fn malformed_token_fails_before_key_lookup() {
        let cache = cache_with_key("key-1");
        let rt = runtime();
        rt.block_on(async {
            let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
            let err = cache
                .decode::<serde_json::Value>("not-a-jwt", &validation)
                .await
                .unwrap_err();
            assert!(matches!(err, JwtError::DecodingFailed(_)), "{err:?}");
        });
    }

    // ---- is_fresh boundary tests (kill cargo-mutants survivors) ----

    #[test]
    fn is_fresh_none_is_stale() {
        assert!(!is_fresh(None, Duration::from_secs(300)));
    }

    #[test]
    fn is_fresh_large_ttl_is_fresh() {
        let at = Some(Instant::now());
        assert!(is_fresh(at, Duration::from_secs(3600)));
    }

    #[test]
    fn is_fresh_zero_ttl_is_stale_after_time_passes() {
        let at = Some(Instant::now());
        std::thread::sleep(Duration::from_millis(1));
        assert!(!is_fresh(at, Duration::ZERO));
    }
}
