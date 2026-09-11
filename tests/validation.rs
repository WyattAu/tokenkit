// Configurable `Validation` behavior: leeway, required_claims, multi-aud,
// validate_exp, validate_nbf.
//
// unwrap/expect are the test signal here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use serde::{Deserialize, Serialize};
use tokenkit::service::{JwtConfig, JwtService};

#[derive(Debug, Serialize, Deserialize)]
struct NumericClaims {
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
}

fn now(secs: i64) -> u64 {
    (chrono::Utc::now().timestamp() + secs) as u64
}

fn claims(exp: u64, iss: &str, aud: Option<&str>) -> NumericClaims {
    NumericClaims {
        sub: Some("user-1".to_string()),
        exp: Some(exp),
        nbf: None,
        iss: Some(iss.to_string()),
        aud: aud.map(str::to_string),
    }
}

#[test]
fn multi_audience_accepts_any_configured_audience() {
    let config = JwtConfig {
        secret: "multi-aud-secret".to_string(),
        audiences: vec!["aud-a".to_string(), "aud-b".to_string()],
        ..Default::default()
    };
    let service = JwtService::new(config);

    let token = service
        .encode(&claims(now(3600), "issuer", Some("aud-a")))
        .unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_ok());

    let token = service
        .encode(&claims(now(3600), "issuer", Some("aud-b")))
        .unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_ok());
}

#[test]
fn multi_audience_rejects_unlisted_audience() {
    let config = JwtConfig {
        secret: "multi-aud-secret".to_string(),
        audiences: vec!["aud-a".to_string(), "aud-b".to_string()],
        ..Default::default()
    };
    let service = JwtService::new(config);
    let token = service
        .encode(&claims(now(3600), "issuer", Some("aud-c")))
        .unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_err());
}

/// The single-audience convenience field folds into the audience set.
#[test]
fn single_audience_convenience_still_validates() {
    let config = JwtConfig {
        secret: "aud-convenience-secret".to_string(),
        audience: Some("only-aud".to_string()),
        ..Default::default()
    };
    let service = JwtService::new(config);
    let token = service
        .encode(&claims(now(3600), "issuer", Some("only-aud")))
        .unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_ok());
    let token = service
        .encode(&claims(now(3600), "issuer", Some("other")))
        .unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_err());
}

/// `audience` and `audiences` are merged, not exclusive.
#[test]
fn audience_and_audiences_merge() {
    let config = JwtConfig {
        secret: "aud-merge-secret".to_string(),
        audience: Some("convenience".to_string()),
        audiences: vec!["list-aud".to_string()],
        ..Default::default()
    };
    let service = JwtService::new(config);
    for aud in ["convenience", "list-aud"] {
        let token = service
            .encode(&claims(now(3600), "issuer", Some(aud)))
            .unwrap();
        assert!(service.decode::<NumericClaims>(&token).is_ok(), "{aud}");
    }
    let token = service
        .encode(&claims(now(3600), "issuer", Some("nope")))
        .unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_err());
}

/// Default leeway (60s, set explicitly by tokenkit) accepts a token that
/// expired a few seconds ago.
#[test]
fn default_leeway_accepts_recently_expired() {
    let config = JwtConfig {
        secret: "leeway-default-secret".to_string(),
        ..Default::default()
    };
    let service = JwtService::new(config);
    let token = service.encode(&claims(now(-5), "issuer", None)).unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_ok());
}

/// Explicit leeway 0 makes even 1-second-past expiry fatal.
#[test]
fn explicit_zero_leeway_rejects_recently_expired() {
    let config = JwtConfig {
        secret: "leeway-zero-secret".to_string(),
        issuer: Some("issuer".to_string()),
        ..JwtConfig::default().with_leeway(0)
    };
    let service = JwtService::new(config);
    let token = service.encode(&claims(now(-5), "issuer", None)).unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_err());
}

/// Custom leeway widens the acceptance window proportionally.
#[test]
fn large_leeway_accepts_older_expiry() {
    let config = JwtConfig {
        secret: "leeway-large-secret".to_string(),
        issuer: Some("issuer".to_string()),
        ..JwtConfig::default().with_leeway(3600)
    };
    let service = JwtService::new(config);
    let token = service.encode(&claims(now(-1800), "issuer", None)).unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_ok());
}

/// Default required claims are still `["exp", "iss"]`: dropping `iss`
/// fails even with a valid signature.
#[test]
fn default_required_claims_reject_missing_iss() {
    let config = JwtConfig {
        secret: "required-default-secret".to_string(),
        ..Default::default()
    };
    let service = JwtService::new(config);
    let token = service
        .encode(&NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now(3600)),
            nbf: None,
            iss: None,
            aud: None,
        })
        .unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_err());
}

/// `required_claims` is configurable: dropping `iss` from the requirement
/// accepts tokens without an issuer.
#[test]
fn custom_required_claims_accept_missing_iss() {
    let config = JwtConfig {
        secret: "required-custom-secret".to_string(),
        ..JwtConfig::default().with_required_claims(vec!["exp".to_string()])
    };
    let service = JwtService::new(config);
    let token = service
        .encode(&NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now(3600)),
            nbf: None,
            iss: None,
            aud: None,
        })
        .unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_ok());
}

/// `validate_exp = false` accepts expired tokens.
#[test]
fn validate_exp_false_accepts_expired() {
    let config = JwtConfig {
        secret: "no-exp-validation-secret".to_string(),
        issuer: Some("issuer".to_string()),
        ..JwtConfig::default().with_validate_exp(false)
    };
    let service = JwtService::new(config);
    let token = service.encode(&claims(now(-3600), "issuer", None)).unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_ok());
}

/// `validate_nbf = true` rejects tokens that are not yet valid.
#[test]
fn validate_nbf_true_rejects_future_token() {
    let config = JwtConfig {
        secret: "nbf-secret".to_string(),
        issuer: Some("issuer".to_string()),
        ..JwtConfig::default().with_validate_nbf(true).with_leeway(0)
    };
    let service = JwtService::new(config);
    let token = service
        .encode(&NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now(7200)),
            nbf: Some(now(3600)),
            iss: Some("issuer".to_string()),
            aud: None,
        })
        .unwrap();
    let decoded = service.decode::<NumericClaims>(&token);
    assert!(decoded.is_err(), "future nbf must be rejected");
}

/// Default (`validate_nbf = false`) ignores a future `nbf`.
#[test]
fn validate_nbf_default_ignores_future_nbf() {
    let config = JwtConfig {
        secret: "nbf-off-secret".to_string(),
        issuer: Some("issuer".to_string()),
        ..Default::default()
    };
    let service = JwtService::new(config);
    let token = service
        .encode(&NumericClaims {
            sub: Some("user-1".to_string()),
            exp: Some(now(7200)),
            nbf: Some(now(3600)),
            iss: Some("issuer".to_string()),
            aud: None,
        })
        .unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_ok());
}
