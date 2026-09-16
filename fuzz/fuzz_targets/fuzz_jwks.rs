#![no_main]

use libfuzzer_sys::fuzz_target;
use tokenkit::jwks::JwksCache;

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
    // Bound input so header parsing stays fast.
    let data = &data[..data.len().min(8192)];
    let parts = split_records(data, 2);
    let token = String::from_utf8_lossy(parts[0]);
    let alg_bits = parts[1].first().copied().unwrap_or(0);

    let mut keys = std::collections::HashMap::new();
    keys.insert(
        "fuzz-key".to_string(),
        jsonwebtoken::DecodingKey::from_secret(b"fuzz-jwks-static-secret"),
    );
    let cache = JwksCache::from_static_keys(keys);

    // Vary the accepted algorithm: header `alg`/`kid` handling (kid lookup,
    // unknown-kid fail-closed, alg mismatch) must return Ok/Err, never panic.
    let alg = match alg_bits % 4 {
        0 => jsonwebtoken::Algorithm::HS256,
        1 => jsonwebtoken::Algorithm::HS512,
        2 => jsonwebtoken::Algorithm::ES256,
        _ => jsonwebtoken::Algorithm::RS256,
    };
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.leeway = u64::from(alg_bits) * 3600;
    validation.required_spec_claims.clear();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("fuzz runtime");
    let claims: Result<serde_json::Value, _> = rt.block_on(cache.decode(&token, &validation));
    let _ = claims;
});
