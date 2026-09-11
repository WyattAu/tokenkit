# tokenkit

[![docs.rs](https://docs.rs/tokenkit/badge.svg)](https://docs.rs/tokenkit)
[![crates.io](https://img.shields.io/crates/v/tokenkit.svg)](https://crates.io/crates/tokenkit)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Type-safe JWT encode/decode for Rust with configurable validation, secret rotation, key rotation, and revocation support.

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `std` | ✅ | Standard-library support. |
| `rotation` | — | Secret rotation: tokens signed with previous secrets keep verifying while new tokens use the newest secret. |
| `revocation` | — | Pluggable `TokenRevocationStore` trait with an in-memory store; decoding rejects revoked `jti`s. |
| `revocation-redis` | — | Redis-backed revocation store for multi-instance deployments (implies `revocation`). |
| `jwks` | — | JWKS fetching and caching with automatic rotation on `kid` miss. |

## Why?

The [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) crate provides low-level JWT primitives but requires manual claim management, validation setup, and doesn't support revocation out of the box. `tokenkit` builds on top of it with a high-level API, standard claims, and optional revocation support.

## Features

- **Type-safe claims** — `StandardClaims` struct with serde derives
- **Configurable algorithms** — HS256/384/512, RS256/384/512, PS256/384/512, ES256/384, EdDSA
- **Configurable validation** — issuer, multi-audience, required claims, explicit leeway, `exp`/`nbf` toggles
- **JWKS support** — fetching + caching with single-flight refresh, algorithm pinning against the key's `alg`, and a `from_static_keys` mode for air-gapped use
- **Token revocation** — pluggable `TokenRevocationStore` trait with bounded in-memory and async Redis implementations
- **JWT helpers** — `extract_bearer_token()`, `build_auth_cookie()`
- **Secret & key rotation** — `kid`-based key selection with a legacy fallback for `kid`-less tokens
- **`#![forbid(unsafe_code)]`** — no unsafe code anywhere

## Quick Start

```rust
use tokenkit::service::{JwtConfig, JwtService, JwtAlgorithm};
use tokenkit::claims::StandardClaims;

let config = JwtConfig {
    algorithm: JwtAlgorithm::HS256,
    secret: "my-secret-key".to_string(),
    ..Default::default()
};

let service = JwtService::new(config);

// Encode
let claims = StandardClaims {
    sub: Some("user-123".to_string()),
    role: Some("admin".to_string()),
    ..Default::default()
};
let token = service.encode_standard(claims).unwrap();

// Decode (async — runs the revocation check when a store is attached)
let decoded = service.decode_standard(&token).await.unwrap();
assert_eq!(decoded.sub.as_deref(), Some("user-123"));
```

## Revocation

```rust
use tokenkit::revocation::InMemoryRevocationStore;
use tokenkit::service::{JwtConfig, JwtService};

let store = Box::new(InMemoryRevocationStore::new()); // bounded: 100k entries
let service = JwtService::new(JwtConfig::default()).with_revocation(store);

// Revoke a token by its jti claim
// store.revoke("token-jti").await.unwrap();
//
// decode_standard is async and fails closed on store errors:
// let claims = service.decode_standard(&token).await.unwrap();
```

## Comparison with Raw `jsonwebtoken`

| Feature | `tokenkit` | `jsonwebtoken` |
|---|---|---|
| Standard claims struct | ✅ | ❌ (manual) |
| Issuer/audience validation | ✅ | Manual setup |
| Token revocation | ✅ | ❌ |
| Bearer token extraction | ✅ | ❌ |
| Cookie builder | ✅ | ❌ |
| Secret rotation support | ✅ | Manual |
| `forbid(unsafe_code)` | ✅ | ❌ |

## License

MIT OR Apache-2.0

## Security

Threat model: [THREAT-MODEL.md](THREAT-MODEL.md).
