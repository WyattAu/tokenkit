use serde::{Deserialize, Serialize};
use tokenkit::service::{JwtAlgorithm, JwtConfig, JwtService};

#[derive(Debug, Serialize, Deserialize)]
struct NumericClaims {
    sub: Option<String>,
    exp: Option<i64>,
    iss: Option<String>,
    aud: Option<String>,
}

fn now_plus_secs(secs: i64) -> i64 {
    chrono::Utc::now().timestamp() + secs
}

/// Kill mutant: `decoding_key -> Ok(Default::default())`.
///
/// If `decoding_key` returns a default (empty) key, `decode` will reject
/// any token signed with the real secret. A successful decode proves the
/// internal key is functional.
#[test]
fn decode_roundtrip_proves_working_key() {
    let config = JwtConfig {
        algorithm: JwtAlgorithm::HS256,
        secret: "test-secret-key-for-mutant-killing".into(),
        issuer: Some("test-issuer".into()),
        ..JwtConfig::default()
    };
    let service = JwtService::new(config);

    let claims = NumericClaims {
        sub: Some("user-42".to_string()),
        exp: Some(now_plus_secs(3600)),
        iss: Some("test-issuer".to_string()),
        aud: None,
    };
    let token = service.encode(&claims).expect("encode should succeed");

    let decoded: NumericClaims = service
        .decode(&token)
        .expect("decode must succeed with matching key");
    assert_eq!(decoded.sub.as_deref(), Some("user-42"));
}
