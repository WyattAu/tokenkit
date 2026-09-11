//! JWKS fetching and caching with automatic rotation on `kid` miss.
//!
//! Enabled with the `jwks` feature. [`JwksCache`](crate::jwks::JwksCache) fetches a JSON Web Key Set
//! from a URL, caches the decoded keys for a configurable TTL, and re-fetches
//! whenever a token references an unknown `kid` — so rotated keys are picked
//! up without restarts or redeploys.
//!
//! # Hardening
//!
//! * **Algorithm pinning**: when a JWK advertises an `alg` member, tokens
//!   whose header claims a different algorithm are rejected with
//!   [`JwtError::AlgorithmMismatch`](crate::error::JwtError::AlgorithmMismatch)
//!   — a key published for one algorithm never verifies tokens claiming
//!   another (alg-confusion defense). When the JWK carries no `alg`, the
//!   caller's configured `Validation` algorithm is the only accepted one
//!   (enforced by `jsonwebtoken`).
//! * **Single-flight refresh**: N concurrent misses trigger exactly one
//!   fetch; waiters reuse the result.
//! * **Minimum refresh interval**: after a fetch, further on-miss refreshes
//!   are skipped for 10 seconds (configurable via
//!   [`JwksCache::with_min_refresh_interval`](crate::jwks::JwksCache::with_min_refresh_interval)),
//!   so a flood of unknown-`kid` tokens cannot hammer the JWKS endpoint.
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

use jsonwebtoken::jwk::{JwkSet, KeyAlgorithm};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use tokio::sync::{Mutex, RwLock};

use crate::error::JwtError;

/// Default cache TTL: 10 minutes.
const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// A cached JWKS key plus the algorithm the JWK advertised (if any).
#[derive(Clone, Debug)]
struct CachedKey {
    key: DecodingKey,
    alg: Option<KeyAlgorithm>,
}

struct CachedKeys {
    keys: HashMap<String, CachedKey>,
    fetched_at: Option<Instant>,
}

/// A cached JWKS key set fetched from a remote URL (or provided locally).
///
/// Keys are cached for [`JwksCache::with_ttl`] (10 minutes by default). A
/// lookup for an unknown `kid`, or an expired cache, triggers a re-fetch —
/// this is the rotation path: newly published keys are picked up on first
/// use, without restarts.
///
/// Refreshes are single-flight and rate-limited: concurrent misses share
/// one fetch, and a fetch is skipped entirely if the last one is newer
/// than [`JwksCache::DEFAULT_MIN_REFRESH_INTERVAL`]. For air-gapped
/// deployments or tests, [`JwksCache::from_static_keys`] builds a cache
/// that never touches the network.
pub struct JwksCache {
    url: String,
    ttl: Duration,
    min_refresh_interval: Duration,
    client: reqwest::Client,
    state: RwLock<CachedKeys>,
    /// Serializes refreshes so concurrent misses coalesce into one fetch.
    refresh_lock: Mutex<()>,
    /// Static key sets never refresh (no URL, no fetches).
    static_keys: bool,
}

impl JwksCache {
    /// Default minimum interval between on-miss refreshes: 10 seconds.
    pub const DEFAULT_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

    /// Create a cache that fetches the JWKS from `url` with the default TTL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ttl: DEFAULT_TTL,
            min_refresh_interval: Self::DEFAULT_MIN_REFRESH_INTERVAL,
            client: reqwest::Client::new(),
            state: RwLock::new(CachedKeys {
                keys: HashMap::new(),
                fetched_at: None,
            }),
            refresh_lock: Mutex::new(()),
            static_keys: false,
        }
    }

    /// Create a cache from locally provided keys — for air-gapped
    /// deployments, offline verification, and tests.
    ///
    /// The cache never fetches: a `kid` that is not in `keys` fails
    /// immediately with [`JwtError::Jwks`].
    pub fn from_static_keys(keys: HashMap<String, DecodingKey>) -> Self {
        let keys: HashMap<String, CachedKey> = keys
            .into_iter()
            .map(|(kid, key)| (kid, CachedKey { key, alg: None }))
            .collect();
        Self {
            url: String::new(),
            ttl: DEFAULT_TTL,
            min_refresh_interval: Self::DEFAULT_MIN_REFRESH_INTERVAL,
            client: reqwest::Client::new(),
            state: RwLock::new(CachedKeys {
                keys,
                fetched_at: Some(Instant::now()),
            }),
            refresh_lock: Mutex::new(()),
            static_keys: true,
        }
    }

    /// Set the cache TTL (how long a fetched set is served without re-fetch).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set the minimum interval between on-miss refreshes. Within this
    /// window after a fetch, refreshes triggered by cache staleness or
    /// unknown `kid`s are skipped (the cached set is served). Defaults to
    /// [`JwksCache::DEFAULT_MIN_REFRESH_INTERVAL`]; set to `Duration::ZERO`
    /// to restore refresh-on-every-miss.
    pub fn with_min_refresh_interval(mut self, interval: Duration) -> Self {
        self.min_refresh_interval = interval;
        self
    }

    /// Use a custom `reqwest` client (e.g. with extra TLS or proxy config).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Re-fetch the JWKS from the configured URL, replacing the cache.
    ///
    /// This is the *forced* refresh: it always performs a fetch, bypassing
    /// the single-flight coalescing and minimum-refresh-interval checks
    /// that guard the automatic on-miss path.
    ///
    /// Keys that cannot be converted to a [`DecodingKey`] (e.g. exotic key
    /// types the backend does not support) are skipped; if no usable keys
    /// remain, an error is returned and the previous cache is kept.
    pub async fn refresh(&self) -> Result<(), JwtError> {
        if self.url.is_empty() {
            return Err(JwtError::Jwks(
                "no JWKS URL configured (static key set)".to_string(),
            ));
        }

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

    /// Automatic refresh path: single-flight (one fetch shared by all
    /// concurrent waiters) and rate-limited (skipped when the last fetch
    /// is within the minimum refresh interval).
    async fn refresh_coalesced(&self) -> Result<(), JwtError> {
        let _guard = self.refresh_lock.lock().await;
        // Coalescing: another task may have refreshed while we waited for
        // the lock; if that fetch is recent enough, reuse it.
        {
            let state = self.state.read().await;
            if is_fresh(state.fetched_at, self.min_refresh_interval) {
                return Ok(());
            }
        }
        self.refresh().await
    }

    /// Resolve the cached key (and its advertised algorithm) for `kid`.
    ///
    /// Serves a fresh cache hit directly. On an unknown `kid` — or a stale
    /// cache — a single-flight refresh runs (rotation) before giving up.
    async fn resolve_key(&self, kid: Option<&str>) -> Result<CachedKey, JwtError> {
        let want = kid.unwrap_or_default();

        {
            let state = self.state.read().await;
            if is_fresh(state.fetched_at, self.ttl)
                && let Some(cached) = state.keys.get(want)
            {
                return Ok(cached.clone());
            }
        }

        if self.static_keys {
            return Err(JwtError::Jwks(format!(
                "unknown key id `{want}` in static key set"
            )));
        }

        // Slow path: stale cache or kid-miss (key rotation) — single-flight
        // refresh, then look up once more.
        self.refresh_coalesced().await?;

        let state = self.state.read().await;
        state
            .keys
            .get(want)
            .cloned()
            .ok_or_else(|| JwtError::Jwks(format!("unknown key id `{want}` after JWKS refresh")))
    }

    /// Resolve the [`DecodingKey`] for `kid`.
    ///
    /// Serves a fresh cache hit directly. On an unknown `kid` — or a stale
    /// cache — the JWKS is re-fetched once (rotation) before giving up.
    pub async fn decoding_key(&self, kid: Option<&str>) -> Result<DecodingKey, JwtError> {
        Ok(self.resolve_key(kid).await?.key)
    }

    /// Decode `token` with the JWKS key referenced by its `kid` header.
    ///
    /// The `kid` is read from the token header (unverified), the matching
    /// key is resolved via [`JwksCache::decoding_key`] (single-flight
    /// refresh on rotation), the token's `alg` header is pinned against
    /// the key's advertised `alg` (alg-confusion defense), and only then
    /// is the token verified against `validation`.
    pub async fn decode<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> Result<T, JwtError> {
        let header = decode_header(token).map_err(|e| JwtError::DecodingFailed(e.to_string()))?;
        let cached = self.resolve_key(header.kid.as_deref()).await?;

        // Algorithm pinning: a JWK that advertises an `alg` must never
        // verify a token claiming a different algorithm.
        if let Some(key_alg) = cached.alg {
            let token_alg = KeyAlgorithm::from(header.alg);
            if key_alg != token_alg {
                return Err(JwtError::AlgorithmMismatch {
                    token_alg: format!("{:?}", header.alg),
                    key_alg: format!("{key_alg:?}"),
                });
            }
        }

        decode::<T>(token, &cached.key, validation)
            .map(|data| data.claims)
            .map_err(|e| JwtError::DecodingFailed(e.to_string()))
    }
}

fn is_fresh(fetched_at: Option<Instant>, ttl: Duration) -> bool {
    fetched_at.is_some_and(|at| at.elapsed() < ttl)
}

/// Convert a [`JwkSet`] into a `kid` → [`CachedKey`] map.
///
/// Keys without a `kid` are stored under the empty string so single-key sets
/// still resolve for tokens that carry no `kid` header. Unconvertible keys
/// are skipped; an error is returned only when nothing usable remains.
fn build_key_map(set: &JwkSet) -> Result<HashMap<String, CachedKey>, JwtError> {
    let mut keys = HashMap::new();
    for jwk in &set.keys {
        let kid = jwk.common.key_id.clone().unwrap_or_default();
        if let Ok(key) = DecodingKey::from_jwk(jwk) {
            keys.insert(
                kid,
                CachedKey {
                    key,
                    alg: jwk.common.key_algorithm,
                },
            );
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

    /// A cache whose fetches (if any) fail fast against the unroutable URL.
    fn cache_with_key(kid: &str) -> JwksCache {
        let cache = JwksCache::new(UNROUTABLE_URL).with_min_refresh_interval(Duration::ZERO);
        let rt = runtime();
        rt.block_on(async {
            let mut state = cache.state.write().await;
            state.keys.insert(
                kid.to_string(),
                CachedKey {
                    key: DecodingKey::from_secret(b"test-secret-for-jwks-cache"),
                    alg: None,
                },
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
        let cache = JwksCache::new(UNROUTABLE_URL)
            .with_ttl(Duration::ZERO)
            .with_min_refresh_interval(Duration::ZERO);
        let rt = runtime();
        rt.block_on(async {
            {
                let mut state = cache.state.write().await;
                state.keys.insert(
                    "key-1".to_string(),
                    CachedKey {
                        key: DecodingKey::from_secret(b"test-secret-for-jwks-cache"),
                        alg: None,
                    },
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
    fn build_key_map_captures_jwk_algorithm() {
        let set: JwkSet = serde_json::from_str(
            r#"{"keys": [
                {"kty": "oct", "k": "YWE", "kid": "k1", "alg": "RS256"},
                {"kty": "oct", "k": "YWI"}
            ]}"#,
        )
        .unwrap();
        let map = build_key_map(&set).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map["k1"].alg, Some(KeyAlgorithm::RS256));
        assert_eq!(map[""].alg, None);
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

    #[test]
    fn static_keys_never_fetch_and_fail_closed_on_unknown_kid() {
        let mut keys = HashMap::new();
        keys.insert(
            "only-key".to_string(),
            DecodingKey::from_secret(b"static-secret"),
        );
        let cache = JwksCache::from_static_keys(keys);
        let rt = runtime();
        rt.block_on(async {
            let key = cache.decoding_key(Some("only-key")).await.unwrap();
            let _ = key;
            // Unknown kid: error mentions the static set, no fetch attempted
            // (there is no URL — a fetch would panic the client on an empty
            // URL, so reaching the error proves none happened).
            let err = cache.decoding_key(Some("other")).await.unwrap_err();
            assert!(
                matches!(&err, JwtError::Jwks(msg) if msg.contains("static key set")),
                "{err:?}"
            );
            let err = cache.refresh().await.unwrap_err();
            assert!(
                matches!(&err, JwtError::Jwks(msg) if msg.contains("static key set")),
                "{err:?}"
            );
        });
    }

    #[test]
    fn static_keys_decode_roundtrip() {
        let mut keys = HashMap::new();
        keys.insert(
            "hmac-1".to_string(),
            DecodingKey::from_secret(b"static-roundtrip-secret"),
        );
        let cache = JwksCache::from_static_keys(keys);
        let rt = runtime();
        rt.block_on(async {
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
            header.kid = Some("hmac-1".to_string());
            let token = jsonwebtoken::encode(
                &header,
                &serde_json::json!({"sub": "static-user"}),
                &jsonwebtoken::EncodingKey::from_secret(b"static-roundtrip-secret"),
            )
            .unwrap();
            let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
            validation.required_spec_claims.clear();
            let claims: serde_json::Value = cache.decode(&token, &validation).await.unwrap();
            assert_eq!(claims["sub"], "static-user");
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
