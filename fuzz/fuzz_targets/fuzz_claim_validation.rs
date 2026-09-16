#![no_main]

use libfuzzer_sys::fuzz_target;
use tokenkit::claims::StandardClaims;
use tokenkit::service::{JwtConfig, JwtService};

/// Split `data` into up to `n` length-prefixed records (u16 LE length +
/// payload). Missing records come back empty; trailing bytes are ignored.
fn split_records(mut data: &[u8], n: usize) -> Vec<&[u8]> {
    let mut parts = Vec::with_capacity(n);
    while parts.len() < n && data.len() >= 2 {
        let len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let rest = &data[2..];
        let take = len.min(rest.len());
        parts.push(&rest[..take]);
        data = &rest[take..];
    }
    while parts.len() < n {
        parts.push(b"");
    }
    parts
}

fuzz_target!(|data: &[u8]| {
    // Bound input so base64url+JSON parsing stays fast.
    let data = &data[..data.len().min(8192)];
    let parts = split_records(data, 5);
    let header = String::from_utf8_lossy(parts[0]);
    let payload = String::from_utf8_lossy(parts[1]);
    let signature = String::from_utf8_lossy(parts[2]);
    let issuer = String::from_utf8_lossy(parts[3]);
    let config = parts[4];

    // Forge a token with fuzzer-controlled header/payload/signature parts —
    // arbitrary base64url+JSON must parse-or-Err, never panic.
    let forged = format!("{header}.{payload}.{signature}");

    // Adversarial validation config: leeway, aud/iss matching, required
    // claims, exp/nbf toggles all driven by fuzz bytes so every claim
    // validation branch runs against hostile tokens.
    let leeway = u64::from(config.first().copied().unwrap_or(0)) << 8
        | u64::from(config.get(1).copied().unwrap_or(0));
    let audience = String::from_utf8_lossy(config.get(2..8).unwrap_or(b"")).to_string();
    let require_exp = config.first().is_some_and(|b| b & 1 == 1);
    let validate_nbf = config.first().is_some_and(|b| b & 2 == 2);

    let config = JwtConfig {
        secret: "fuzz-test-secret-key".to_string(),
        issuer: Some(issuer.to_string()),
        leeway: Some(leeway),
        audiences: if audience.is_empty() {
            Vec::new()
        } else {
            vec![audience]
        },
        validate_exp: require_exp,
        validate_nbf,
        ..Default::default()
    };
    let service = JwtService::new(config);

    let _ = service.decode::<StandardClaims>(&forged);
    let _ = service.validate(&forged);

    // The raw buffer as a token too: dot-stripping and segment splitting on
    // arbitrary bytes must not panic.
    let raw = String::from_utf8_lossy(data);
    let _ = service.decode::<StandardClaims>(&raw);
});
