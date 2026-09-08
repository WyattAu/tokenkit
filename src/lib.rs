#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Type-safe JWT encode/decode for Rust with configurable validation,
//! secret rotation, key rotation, and revocation support.
//!
//! # Quick Start
//!
//! ```
//! use tokenkit::service::{JwtConfig, JwtService, JwtAlgorithm};
//! use tokenkit::claims::StandardClaims;
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct Claims {
//!     sub: Option<String>,
//!     exp: Option<u64>,
//!     iss: Option<String>,
//! }
//!
//! let config = JwtConfig {
//!     algorithm: JwtAlgorithm::HS256,
//!     secret: "my-secret-key".to_string(),
//!     issuer: Some("my-app".to_string()),
//!     ..Default::default()
//! };
//!
//! let service = JwtService::new(config);
//! let claims = Claims {
//!     sub: Some("user-123".to_string()),
//!     exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
//!     iss: Some("my-app".to_string()),
//! };
//!
//! let token = service.encode(&claims).unwrap();
//! let decoded: Claims = service.decode(&token).unwrap();
//! assert_eq!(decoded.sub.as_deref(), Some("user-123"));
//! ```

/// JWT claims types.
pub mod claims;
/// Error types.
pub mod error;
/// Extractors for HTTP authorization headers and cookies.
pub mod extractors;
/// JWT service for encoding, decoding, and validation.
pub mod service;

/// JWKS fetching and caching with automatic rotation on `kid` miss.
#[cfg(feature = "jwks")]
pub mod jwks;

/// Token revocation: pluggable `TokenRevocationStore` trait with
/// in-memory and Redis-backed implementations.
#[cfg(feature = "revocation")]
pub mod revocation;

// Tests exercise failure paths and invariants directly; unwrap/expect,
// slicing, and panicking asserts are acceptable here — violations
// surface as test failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::claims::StandardClaims;
    use super::error::JwtError;
    use super::extractors::{build_auth_cookie, extract_bearer_token};
    use super::service::{JwtConfig, JwtService};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct NumericClaims {
        sub: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exp: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        iss: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<String>,
    }

    fn now_plus_secs(secs: u64) -> u64 {
        chrono::Utc::now().timestamp() as u64 + secs
    }

    #[test]
    fn jwt_config_default_is_hs256() {
        let config = JwtConfig::default();
        assert_eq!(config.algorithm, super::service::JwtAlgorithm::HS256);
        assert_eq!(config.access_token_ttl, 3600);
        assert_eq!(config.refresh_token_ttl, 604800);
    }

    #[test]
    fn jwt_config_short_secret_works_for_hmac() {
        let config = JwtConfig {
            secret: "ab".to_string(),
            issuer: Some("test-issuer".to_string()),
            ..Default::default()
        };
        let service = JwtService::new(config);
        let claims = NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now_plus_secs(3600)),
            iss: Some("test-issuer".to_string()),
            aud: None,
        };
        let token = service.encode(&claims).unwrap();
        let decoded: NumericClaims = service.decode(&token).unwrap();
        assert_eq!(decoded.sub.as_deref(), Some("user-1"));
    }

    #[test]
    fn jwt_service_encode_decode_roundtrip() {
        let config = JwtConfig {
            secret: "a-valid-secret-key-for-testing".to_string(),
            issuer: Some("test-issuer".to_string()),
            ..Default::default()
        };
        let service = JwtService::new(config);

        let claims = NumericClaims {
            sub: Some("user-42".to_string()),
            exp: Some(now_plus_secs(3600)),
            iss: Some("test-issuer".to_string()),
            aud: None,
        };

        let token = service.encode(&claims).unwrap();
        let decoded: NumericClaims = service.decode(&token).unwrap();

        assert_eq!(decoded.sub.as_deref(), Some("user-42"));
        assert_eq!(decoded.iss.as_deref(), Some("test-issuer"));
    }

    #[test]
    fn jwt_service_encode_decode_with_issuer_audience() {
        let config = JwtConfig {
            secret: "test-secret-key-123".to_string(),
            issuer: Some("test-issuer".to_string()),
            audience: Some("test-audience".to_string()),
            ..Default::default()
        };
        let service = JwtService::new(config);

        let claims = NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now_plus_secs(3600)),
            iss: Some("test-issuer".to_string()),
            aud: Some("test-audience".to_string()),
        };

        let token = service.encode(&claims).unwrap();
        let decoded: NumericClaims = service.decode(&token).unwrap();
        assert_eq!(decoded.iss.as_deref(), Some("test-issuer"));
        assert_eq!(decoded.aud.as_deref(), Some("test-audience"));
    }

    #[test]
    fn jwt_service_wrong_secret_fails() {
        let config1 = JwtConfig {
            secret: "secret-one".to_string(),
            ..Default::default()
        };
        let config2 = JwtConfig {
            secret: "secret-two".to_string(),
            ..Default::default()
        };
        let service1 = JwtService::new(config1);
        let service2 = JwtService::new(config2);

        let claims = NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now_plus_secs(3600)),
            iss: None,
            aud: None,
        };
        let token = service1.encode(&claims).unwrap();
        let result = service2.decode::<NumericClaims>(&token);
        assert!(result.is_err());
    }

    #[test]
    fn standard_claims_serialization_roundtrip() {
        let claims = StandardClaims {
            sub: Some("user-100".to_string()),
            iss: Some("issuer".to_string()),
            aud: Some("audience".to_string()),
            role: Some("editor".to_string()),
            permissions: vec!["edit".to_string()],
            ..Default::default()
        };

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: StandardClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.sub.as_deref(), Some("user-100"));
        assert_eq!(deserialized.iss.as_deref(), Some("issuer"));
        assert_eq!(deserialized.aud.as_deref(), Some("audience"));
        assert_eq!(deserialized.role.as_deref(), Some("editor"));
        assert_eq!(deserialized.permissions, vec!["edit"]);
    }

    #[test]
    fn standard_claims_skips_none_fields() {
        let claims = StandardClaims::default();
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("sub"));
        assert!(!json.contains("iss"));
        assert!(!json.contains("role"));
    }

    #[test]
    fn standard_claims_with_extra_fields() {
        let mut extra = std::collections::HashMap::new();
        extra.insert("custom_key".to_string(), serde_json::json!("custom_value"));
        let claims = StandardClaims {
            sub: Some("user-1".to_string()),
            extra,
            ..Default::default()
        };
        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: StandardClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.extra.get("custom_key").unwrap(),
            &serde_json::json!("custom_value")
        );
    }

    #[test]
    fn extract_bearer_token_valid() {
        assert_eq!(
            extract_bearer_token("Bearer abc123"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn extract_bearer_token_with_spaces() {
        assert_eq!(
            extract_bearer_token("Bearer   token-with-spaces  "),
            Some("token-with-spaces".to_string())
        );
    }

    #[test]
    fn extract_bearer_token_wrong_scheme() {
        assert_eq!(extract_bearer_token("Basic abc123"), None);
    }

    #[test]
    fn extract_bearer_token_empty() {
        assert_eq!(extract_bearer_token("Bearer "), None);
        assert_eq!(extract_bearer_token(""), None);
    }

    #[test]
    fn build_auth_cookie_format() {
        let cookie = build_auth_cookie("session", "jwt_token_here", 3600, true);
        assert!(cookie.contains("session=jwt_token_here"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Secure"));
    }

    #[test]
    fn build_auth_cookie_no_secure() {
        let cookie = build_auth_cookie("sid", "tok", 600, false);
        assert!(!cookie.contains("Secure"));
        assert!(cookie.contains("sid=tok"));
    }

    #[test]
    fn jwt_error_display_messages() {
        assert_eq!(JwtError::EncodingFailed.to_string(), "failed to encode JWT");
        assert_eq!(
            JwtError::DecodingFailed("bad".to_string()).to_string(),
            "failed to decode JWT: bad"
        );
        assert_eq!(JwtError::Expired.to_string(), "token has expired");
        assert_eq!(JwtError::InvalidSignature.to_string(), "invalid signature");
        assert_eq!(JwtError::Revoked.to_string(), "token has been revoked");
        assert_eq!(
            JwtError::InvalidSecret("weak".to_string()).to_string(),
            "invalid secret or key: weak"
        );
        assert_eq!(
            JwtError::KeyLoading("pem err".to_string()).to_string(),
            "failed to load signing key: pem err"
        );
    }

    /// REQ-TK-107: `Debug` for `JwtConfig` must redact the signing secret —
    /// configs get logged, and the secret is the whole game for HMAC JWTs.
    #[test]
    fn jwt_config_debug_redacts_secret() {
        let config = JwtConfig {
            secret: "super-secret-value".to_string(),
            issuer: Some("iss".to_string()),
            ..Default::default()
        };
        let dbg = format!("{config:?}");
        assert!(!dbg.contains("super-secret-value"));
        assert!(dbg.contains("<redacted>"));
    }

    /// REQ-TK-101: an expired token must be rejected, not accepted.
    #[test]
    fn expired_token_rejected() {
        let config = JwtConfig {
            secret: "expired-test-secret".to_string(),
            ..Default::default()
        };
        let service = JwtService::new(config);
        let claims = NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now_plus_secs(0).saturating_sub(3600)), // 1h in the past
            iss: None,
            aud: None,
        };
        let token = service.encode(&claims).unwrap();
        let result = service.decode::<NumericClaims>(&token);
        assert!(result.is_err());
    }

    /// REQ-TK-102: `exp` and `iss` are required spec claims — a token
    /// missing them is rejected even with a valid signature.
    #[test]
    fn missing_required_claims_rejected() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct BareClaims {
            sub: Option<String>,
        }
        let config = JwtConfig {
            secret: "required-claims-secret".to_string(),
            ..Default::default()
        };
        let service = JwtService::new(config);
        let token = service
            .encode(&BareClaims {
                sub: Some("user-1".to_string()),
            })
            .unwrap();
        let result = service.decode::<NumericClaims>(&token);
        assert!(result.is_err());
    }

    /// REQ-TK-103: a token whose `iss` does not match the configured issuer
    /// is rejected (signed by the same secret — only the issuer differs).
    #[test]
    fn issuer_mismatch_rejected() {
        let config = JwtConfig {
            secret: "issuer-test-secret".to_string(),
            issuer: Some("expected-issuer".to_string()),
            ..Default::default()
        };
        let service = JwtService::new(config);
        let claims = NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now_plus_secs(3600)),
            iss: Some("evil-issuer".to_string()),
            aud: None,
        };
        let token = service.encode(&claims).unwrap();
        let result = service.decode::<NumericClaims>(&token);
        assert!(result.is_err());
    }

    /// REQ-TK-104: a token whose `aud` does not match the configured
    /// audience is rejected.
    #[test]
    fn audience_mismatch_rejected() {
        let config = JwtConfig {
            secret: "aud-test-secret".to_string(),
            audience: Some("expected-aud".to_string()),
            ..Default::default()
        };
        let service = JwtService::new(config);
        let claims = NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now_plus_secs(3600)),
            iss: None,
            aud: Some("other-aud".to_string()),
        };
        let token = service.encode(&claims).unwrap();
        let result = service.decode::<NumericClaims>(&token);
        assert!(result.is_err());
    }

    /// REQ-TK-105: algorithm pinning — a token signed under a different
    /// algorithm (here HS384) must be rejected by an HS256 service. This is
    /// the JWT algorithm-confusion defense.
    #[test]
    fn cross_algorithm_token_rejected() {
        let hs384_service = JwtService::new(JwtConfig {
            secret: "shared-secret-value".to_string(),
            algorithm: super::service::JwtAlgorithm::HS384,
            ..Default::default()
        });
        let hs256_service = JwtService::new(JwtConfig {
            secret: "shared-secret-value".to_string(),
            algorithm: super::service::JwtAlgorithm::HS256,
            ..Default::default()
        });
        // `iss` must be present so the ONLY rejection reason can be the
        // algorithm mismatch: required-spec-claim validation would otherwise
        // reject the token before the pinned-algorithm check is reached,
        // masking the very defense under test (REQ-TK-105).
        let claims = NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now_plus_secs(3600)),
            iss: Some("issuer".to_string()),
            aud: None,
        };
        let token = hs384_service.encode(&claims).unwrap();
        let result = hs256_service.decode::<NumericClaims>(&token);
        assert!(result.is_err());
    }

    /// REQ-TK-107: `Debug` for `JwtConfig` surfaces the configured algorithm
    /// name (operators must be able to tell which alg a config uses without
    /// un-redacting anything).
    #[test]
    fn jwt_config_debug_shows_algorithm() {
        let hs384 = JwtConfig {
            algorithm: super::service::JwtAlgorithm::HS384,
            ..Default::default()
        };
        assert!(format!("{hs384:?}").contains("HS384"), "{hs384:?}");

        let rs256 = JwtConfig {
            algorithm: super::service::JwtAlgorithm::RS256,
            ..Default::default()
        };
        assert!(format!("{rs256:?}").contains("RS256"), "{rs256:?}");
    }

    /// REQ-TK-003: `encode_standard` stamps `exp` in the future (now + ttl)
    /// and `iss` from the config — the minted token must validate.
    #[test]
    fn encode_standard_mints_a_valid_token() {
        let config = JwtConfig {
            secret: "standard-mint-secret".to_string(),
            issuer: Some("issuer".to_string()),
            ..Default::default()
        };
        let service = JwtService::new(config);
        let claims = StandardClaims {
            sub: Some("user-1".to_string()),
            ..Default::default()
        };
        let token = service.encode_standard(claims).unwrap();
        let decoded = service.validate(&token).unwrap();
        assert_eq!(decoded.sub.as_deref(), Some("user-1"));
    }

    /// REQ-TK-101: `validate` rejects expired tokens and returns the real
    /// claims for a live token (never default/anonymous claims).
    #[test]
    fn validate_rejects_expired_and_returns_real_claims() {
        let config = JwtConfig {
            secret: "validate-test-secret".to_string(),
            issuer: Some("issuer".to_string()),
            ..Default::default()
        };
        let service = JwtService::new(config);

        let expired = NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now_plus_secs(0).saturating_sub(3600)),
            iss: Some("issuer".to_string()),
            aud: None,
        };
        let token = service.encode(&expired).unwrap();
        assert!(service.validate(&token).is_err());

        let fresh = NumericClaims {
            sub: Some("user-2".to_string()),
            exp: Some(now_plus_secs(3600)),
            iss: Some("issuer".to_string()),
            aud: None,
        };
        let token = service.encode(&fresh).unwrap();
        let claims = service.validate(&token).unwrap();
        assert_eq!(claims.sub.as_deref(), Some("user-2"));
    }

    /// REQ-TK-112 (rotation feature): tokens signed with an old secret keep
    /// verifying while rotation secrets are configured; unknown secrets fail.
    #[cfg(feature = "rotation")]
    #[test]
    fn rotation_accepts_old_secret_tokens() {
        let old_service = JwtService::new(JwtConfig {
            secret: "old-secret".to_string(),
            ..Default::default()
        });
        let claims = NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now_plus_secs(3600)),
            iss: Some("issuer".to_string()),
            aud: None,
        };
        let token = old_service.encode(&claims).unwrap();

        // Rotated service: signs with "new-secret", still accepts old.
        let rotated = JwtService::new(JwtConfig::with_rotation_secrets(
            super::service::JwtAlgorithm::HS256,
            vec!["new-secret".to_string(), "old-secret".to_string()],
        ));
        let decoded: NumericClaims = rotated.decode(&token).unwrap();
        assert_eq!(decoded.sub.as_deref(), Some("user-1"));

        // New tokens verify with the new primary secret.
        let new_token = rotated.encode(&claims).unwrap();
        let primary_only = JwtService::new(JwtConfig {
            secret: "new-secret".to_string(),
            ..Default::default()
        });
        assert!(primary_only.decode::<NumericClaims>(&new_token).is_ok());
        assert!(primary_only.decode::<NumericClaims>(&token).is_err());
    }

    /// REQ-TK-110/REQ-TK-111 (revocation feature): a revoked `jti` is
    /// rejected by `decode_standard`; a non-revoked token passes; revocation
    /// is idempotent and visible across handles of the same store.
    #[cfg(feature = "revocation")]
    #[test]
    fn revoked_token_rejected_by_decode_standard() {
        use super::revocation::InMemoryRevocationStore;
        use std::sync::Arc;

        // No tokio "macros" feature in this crate's dep set — drive the
        // async store API through a manually built runtime.
        let rt = tokio::runtime::Runtime::new().unwrap();

        let secret = "revocation-test-secret".to_string();
        let store = Arc::new(InMemoryRevocationStore::new());

        let service = JwtService::new(JwtConfig {
            secret,
            ..Default::default()
        })
        .with_revocation(Box::new(InMemoryRevocationStore::new()));

        let claims = StandardClaims {
            sub: Some("user-1".to_string()),
            iss: Some("issuer".to_string()),
            jti: Some("jti-to-revoke".to_string()),
            exp: Some(chrono::Utc::now() + chrono::Duration::seconds(3600)),
            ..Default::default()
        };
        let token = service.encode_standard(claims).unwrap();

        // decode_standard enters the tokio context internally
        // (block_in_place), so all calls must run inside the runtime.
        rt.block_on(async {
            use super::revocation::TokenRevocationStore as _;

            // Not revoked yet.
            assert!(service.decode_standard(&token).is_ok());

            // Revoke, then verify the check fires from a service sharing the
            // same store state.
            store.revoke("jti-to-revoke").await.unwrap();
            assert!(store.is_revoked("jti-to-revoke").await.unwrap());
            // Idempotent revoke.
            store.revoke("jti-to-revoke").await.unwrap();

            let service_with_state = JwtService::new(JwtConfig {
                secret: "revocation-test-secret".to_string(),
                ..Default::default()
            })
            .with_revocation(Box::new(SharedStore(Arc::clone(&store))));
            let err = service_with_state
                .decode_standard(&token)
                .expect_err("revoked token must be rejected");
            assert!(matches!(err, JwtError::Revoked));
        });
    }

    /// Adapter sharing an `Arc<InMemoryRevocationStore>` with a test.
    #[cfg(feature = "revocation")]
    struct SharedStore(std::sync::Arc<super::revocation::InMemoryRevocationStore>);

    #[cfg(feature = "revocation")]
    #[async_trait::async_trait]
    impl super::revocation::TokenRevocationStore for SharedStore {
        async fn revoke(&self, jti: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.0.revoke(jti).await
        }

        async fn is_revoked(
            &self,
            jti: &str,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            self.0.is_revoked(jti).await
        }
    }
}

// Tests exercise failure paths and invariants directly; unwrap/expect,
// slicing, and panicking asserts are acceptable here — violations
// surface as test failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod proptest_tests {
    use super::service::{JwtConfig, JwtService};
    use proptest::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct NumericClaims {
        sub: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exp: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        iss: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<String>,
    }

    fn arb_standard_claims() -> impl Strategy<Value = super::claims::StandardClaims> {
        (
            prop::option::of("[a-z0-9_-]{1,20}"),
            prop::option::of("[a-z0-9_-]{1,20}"),
            prop::option::of("[a-z]{1,10}"),
            prop::collection::vec("[a-z]{1,10}", 0..5),
        )
            .prop_map(
                |(sub, aud, role, permissions)| super::claims::StandardClaims {
                    sub,
                    iss: None,
                    aud,
                    exp: None,
                    iat: None,
                    jti: None,
                    role,
                    permissions,
                    extra: std::collections::HashMap::new(),
                },
            )
    }

    proptest! {
        #[test]
        fn jwt_roundtrip(sub in "[a-z0-9_-]{1,20}") {
            let config = JwtConfig {
                secret: "test-secret-key-12345".to_string(),
                issuer: Some("test-issuer".to_string()),
                ..Default::default()
            };
            let service = JwtService::new(config);
            let claims = NumericClaims {
                sub: Some(sub.clone()),
                exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
                iss: Some("test-issuer".to_string()),
                aud: None,
            };
            let token = service.encode(&claims).unwrap();
            let decoded: NumericClaims = service.decode(&token).unwrap();
            prop_assert_eq!(decoded.sub.as_deref(), Some(sub.as_str()));
            prop_assert_eq!(decoded.iss.as_deref(), Some("test-issuer"));
        }

        #[test]
        fn jwt_wrong_secret_fails(iss in "[a-z0-9_-]{1,20}") {
            let config1 = JwtConfig {
                secret: "secret-one-for-testing".to_string(),
                issuer: Some(iss.clone()),
                ..Default::default()
            };
            let config2 = JwtConfig {
                secret: "secret-two-for-testing".to_string(),
                issuer: Some(iss),
                ..Default::default()
            };
            let service1 = JwtService::new(config1);
            let service2 = JwtService::new(config2);
            let claims = NumericClaims {
                sub: Some("user-1".to_string()),
                exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
                iss: None,
                aud: None,
            };
            let token = service1.encode(&claims).unwrap();
            let result = service2.decode::<NumericClaims>(&token);
            prop_assert!(result.is_err());
        }

        #[test]
        fn jwt_malformed_token_fails(data in "\\PC{1,500}") {
            let config = JwtConfig {
                secret: "a-valid-secret".to_string(),
                ..Default::default()
            };
            let service = JwtService::new(config);
            let result = service.decode::<NumericClaims>(&data);
            prop_assert!(result.is_err());
        }

        #[test]
        fn claims_serialization_roundtrip(claims in arb_standard_claims()) {
            let json = serde_json::to_string(&claims).unwrap();
            let deserialized: super::claims::StandardClaims = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(deserialized.sub, claims.sub);
            prop_assert_eq!(deserialized.iss, claims.iss);
            prop_assert_eq!(deserialized.aud, claims.aud);
            prop_assert_eq!(deserialized.role, claims.role);
            prop_assert_eq!(deserialized.permissions, claims.permissions);
        }
    }
}
