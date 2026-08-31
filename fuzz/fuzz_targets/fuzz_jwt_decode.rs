#![no_main]

use libfuzzer_sys::fuzz_target;
use tokenkit::claims::StandardClaims;
use tokenkit::service::{JwtConfig, JwtService};
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    // Convert arbitrary bytes to a string (lossy) to use as a token
    let token = String::from_utf8_lossy(data);

    // Create a JWT service with a known secret
    let config = JwtConfig {
        secret: Zeroizing::new("fuzz-test-secret-key".to_string()),
        issuer: Some("fuzz-test".to_string()),
        ..Default::default()
    };
    let service = JwtService::new(config);

    // Fuzz decode with arbitrary byte strings — malformed tokens must not panic
    let _ = service.decode::<StandardClaims>(&token);
});
