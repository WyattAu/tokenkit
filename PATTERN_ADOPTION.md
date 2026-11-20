# Pattern adoption: tokenkit

Type-safe JWT encode/decode with rotation and revocation. Declared per
`pattern-standards/references/adoption-format.md`.

| Pattern | Status | Evidence |
|---|---|---|
| P114 | adopted | src/service.rs:1 (JwtService with a closed JwtAlgorithm allowlist and validation before decode) and tests/jwks_hardening.rs:1 |
| P115 | adopted | tests/rotation.rs:1 (kid header pins the verification key; try-every-key fallback is reserved for legacy tokens) and tests/algorithms.rs:1 (roundtrips for every supported algorithm) |
| P50 | adopted | tests/revocation_redis.rs:6 (revocation store integration runs against a real Redis in testcontainers, not an in-process mock) |
