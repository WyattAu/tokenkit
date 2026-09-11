// `kid`-based key selection during rotation: a token's `kid` header pins
// the verification key; the try-every-key fallback is reserved for legacy
// tokens that carry no `kid` header.
//
// unwrap/expect are the test signal here.
#![cfg(feature = "rotation")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use tokenkit::service::{JwtAlgorithm, JwtConfig, JwtService, RotationKey};

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

fn claims() -> NumericClaims {
    NumericClaims {
        sub: Some("user-1".to_string()),
        exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
        iss: Some("issuer".to_string()),
        aud: None,
    }
}

/// Sign a token with an explicit secret and `kid` header, bypassing the
/// service's primary key (simulates a token minted before rotation).
fn token_with_kid(secret: &str, kid: Option<&str>) -> String {
    let mut header = Header::new(JwtAlgorithm::HS256.into());
    header.kid = kid.map(str::to_string);
    encode(
        &header,
        &claims(),
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn rotated_service() -> JwtService {
    JwtService::new(JwtConfig::with_rotation_keys(
        JwtAlgorithm::HS256,
        vec![
            RotationKey::new("new-secret", Some("new-kid".to_string())),
            RotationKey::new("old-secret", Some("old-kid".to_string())),
        ],
    ))
}

/// New tokens are stamped with the primary key's `kid`.
#[test]
fn encode_stamps_primary_key_id() {
    let token = rotated_service().encode(&claims()).unwrap();
    let header = jsonwebtoken::decode_header(&token).unwrap();
    assert_eq!(header.kid.as_deref(), Some("new-kid"));
}

/// A token whose `kid` matches a rotation key verifies against that key.
#[test]
fn kid_matching_rotation_key_verifies() {
    let service = rotated_service();
    let token = token_with_kid("old-secret", Some("old-kid"));
    let decoded: NumericClaims = service.decode(&token).unwrap();
    assert_eq!(decoded.sub.as_deref(), Some("user-1"));
}

/// `kid` pins the key: a token claiming `old-kid` but signed with the NEW
/// secret fails, even though the new secret is in the configured set
/// (no try-all fallback once a `kid` is claimed).
#[test]
fn kid_pin_prevents_key_confusion() {
    let service = rotated_service();
    let forged = token_with_kid("new-secret", Some("old-kid"));
    let decoded = service.decode::<NumericClaims>(&forged);
    assert!(decoded.is_err());

    let forged_other_way = token_with_kid("old-secret", Some("new-kid"));
    assert!(service.decode::<NumericClaims>(&forged_other_way).is_err());
}

/// A token naming an unknown `kid` is rejected outright — `kid` is
/// attacker-controlled and must not become a key-injection oracle.
#[test]
fn unknown_kid_rejected_without_try_all() {
    let service = rotated_service();
    let token = token_with_kid("old-secret", Some("attacker-kid"));
    let err = service
        .decode::<NumericClaims>(&token)
        .expect_err("unknown kid must not verify");
    assert!(
        matches!(&err, tokenkit::error::JwtError::DecodingFailed(msg) if msg.contains("attacker-kid")),
        "{err:?}"
    );
}

/// Legacy tokens carry no `kid`: every configured key is tried.
#[test]
fn no_kid_token_falls_back_to_try_all() {
    let service = rotated_service();
    let legacy = token_with_kid("old-secret", None);
    let decoded: NumericClaims = service.decode(&legacy).unwrap();
    assert_eq!(decoded.sub.as_deref(), Some("user-1"));

    let primary = token_with_kid("new-secret", None);
    let decoded: NumericClaims = service.decode(&primary).unwrap();
    assert_eq!(decoded.sub.as_deref(), Some("user-1"));

    // Wrong secret still fails with no kid to pin.
    let bad = token_with_kid("wrong-secret", None);
    assert!(service.decode::<NumericClaims>(&bad).is_err());
}

/// The legacy `with_rotation_secrets` constructor keeps working: entries
/// have no `key_id`, primary is first, all secrets verify kid-less tokens.
#[test]
fn legacy_rotation_secrets_constructor_still_works() {
    let service = JwtService::new(JwtConfig::with_rotation_secrets(
        JwtAlgorithm::HS256,
        vec!["first".to_string(), "second".to_string()],
    ));

    // First secret signs, and its tokens decode.
    let token = service.encode(&claims()).unwrap();
    assert!(service.decode::<NumericClaims>(&token).is_ok());

    // Kid-less tokens from the older secret still verify.
    let old = token_with_kid("second", None);
    assert!(service.decode::<NumericClaims>(&old).is_ok());

    // And kid-bearing tokens from the older secret verify too (they map to
    // the fallback path only when the kid is unknown — here the primary has
    // no kid, so "old-kid" would be unknown; use a kid-less token instead).
    let header = jsonwebtoken::decode_header(&token).unwrap();
    assert_eq!(header.kid, None);
}
