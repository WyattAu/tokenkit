#![forbid(unsafe_code)]

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

pub mod claims;
pub mod error;
pub mod extractors;
pub mod service;

#[cfg(feature = "revocation")]
pub mod revocation;

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
        assert_eq!(
            JwtError::EncodingFailed.to_string(),
            "failed to encode JWT"
        );
        assert_eq!(
            JwtError::DecodingFailed("bad".to_string()).to_string(),
            "failed to decode JWT: bad"
        );
        assert_eq!(JwtError::Expired.to_string(), "token has expired");
        assert_eq!(
            JwtError::InvalidSignature.to_string(),
            "invalid signature"
        );
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
}
