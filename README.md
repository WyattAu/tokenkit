| `rotation` |; | Secret rotation: tokens signed with previous secrets keep verifying while new tokens use the newest secret. |
| `revocation` |; | Pluggable `TokenRevocationStore` trait with an in-memory store; decoding rejects revoked `jti`s. |
| `revocation-redis` |; | Redis-backed revocation store for multi-instance deployments (implies `revocation`). |
| `jwks` |; | JWKS fetching and caching with automatic rotation on `kid` miss. |
- **Type-safe claims**; `StandardClaims` struct with serde derives
- **Configurable algorithms**; HS256/384/512, RS256/384/512, PS256/384/512, ES256/384, EdDSA
- **Configurable validation**; issuer, multi-audience, required claims, explicit leeway, `exp`/`nbf` toggles
- **JWKS support**; fetching + caching with single-flight refresh, algorithm pinning against the key's `alg`, and a `from_static_keys` mode for air-gapped use
- **Token revocation**; pluggable `TokenRevocationStore` trait with bounded in-memory and async Redis implementations
- **JWT helpers**; `extract_bearer_token()`, `build_auth_cookie()`
- **Secret & key rotation**; `kid`-based key selection with a legacy fallback for `kid`-less tokens
- **`#![forbid(unsafe_code)]`**; no unsafe code anywhere
// Decode (async; runs the revocation check when a store is attached)
- New tests added during this baseline: per-algorithm JOSE-header pinning in `tests/algorithms.rs` (kills constructor/builder algorithm swaps; the JWT algorithm-confusion class), `RotationKey` debug redaction, and `!is_empty()` on a non-empty revocation store.