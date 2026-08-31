#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};
use tokenkit::service::{JwtConfig, JwtService};
use zeroize::Zeroizing;

/// Minimal claims struct for fuzzing encode with arbitrary values.
#[derive(Serialize, Deserialize, Debug)]
struct FuzzClaims {
    sub: Option<String>,
    iss: Option<String>,
    aud: Option<String>,
    exp: Option<u64>,
    #[serde(flatten)]
    extra: std::collections::HashMap<String, serde_json::Value>,
}

fuzz_target!(|data: &[u8]| {
    // Try to interpret the fuzzer data as JSON claims
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(claims) = serde_json::from_str::<FuzzClaims>(s) {
            let config = JwtConfig {
                secret: Zeroizing::new("fuzz-test-secret-key".to_string()),
                issuer: Some("fuzz-test".to_string()),
                ..Default::default()
            };
            let service = JwtService::new(config);

            // Fuzz encode with arbitrary claims — must not panic
            if let Ok(token) = service.encode(&claims) {
                // If encoding succeeded, verify decode roundtrip works
                let _ = service.decode::<FuzzClaims>(&token);
            }
        }
    }
});
