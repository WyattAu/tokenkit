# tokenkit

Type-safe JWT encode/decode for Rust with configurable validation, secret rotation, key rotation, and revocation support.

## Why?

The [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) crate provides low-level JWT primitives but requires manual claim management, validation setup, and doesn't support revocation out of the box. `tokenkit` builds on top of it with a high-level API, standard claims, and optional revocation support.

## Features

- **Type-safe claims** — `StandardClaims` struct with serde derives
- **Configurable algorithms** — HS256/384/512, RS256/384/512
- **Built-in validation** — issuer, audience, expiration checks
- **Token revocation** — pluggable `TokenRevocationStore` trait with in-memory implementation
- **JWT helpers** — `extract_bearer_token()`, `build_auth_cookie()`
- **Secret & key rotation** — swap `JwtConfig` without downtime
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

// Decode
let decoded = service.decode_standard(&token).unwrap();
assert_eq!(decoded.sub.as_deref(), Some("user-123"));
```

## Revocation

```rust
use tokenkit::revocation::InMemoryRevocationStore;
use tokenkit::service::{JwtConfig, JwtService};

let store = Box::new(InMemoryRevocationStore::new());
let service = JwtService::new(JwtConfig::default()).with_revocation(store);

// Revoke a token by its jti claim
// store.revoke("token-jti").await.unwrap();
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
