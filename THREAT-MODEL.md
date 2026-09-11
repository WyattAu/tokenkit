# Threat Model — tokenkit

Status: **v1.0** · Method: STRIDE over the public API surface
(`JwtService::encode`/`decode`/`decode_standard`/`validate`,
`JwtConfig`, `extractors`, `revocation` stores).

Trust boundaries: (1) the token string arriving from clients (hostile),
(2) the `Authorization` header / cookie the caller feeds to `extractors`,
(3) the revocation backend (in-memory or Redis), (4) the
`jsonwebtoken`/`redis` dependency tree.

## Assets

| ID | Asset | Example |
|----|-------|---------|
| A1 | Token authenticity | `alg`-confusion or wrong-key forgery accepted |
| A2 | Signing secrets (HMAC keys / RSA PEMs) | Secret leaked via `Debug` or logs |
| A3 | Claim integrity (`exp`, `iss`, `aud`, `jti`) | Expired or revoked token accepted |
| A4 | Availability | Malformed token causes panic or Redis outage stalls auth |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Verifying test |
|---|--------|----------|---------|------------|----------------|
| T1 | Algorithm confusion (`alg: none`, HS/RS mixing) | Spoofing | `decode`, JWKS `decode` | `Validation::new(config.algorithm)` pins the expected algorithm; the client-controlled header algorithm is matched by `jsonwebtoken` against it. JWKS path additionally pins the header `alg` against the JWK's own `alg` member (`JwtError::AlgorithmMismatch`) | `src/lib.rs::cross_algorithm_token_rejected`, `tests/jwks_hardening.rs::jwk_alg_pinned_rejects_mismatched_token_alg` |
| T2 | Forged signature with a different secret | Spoofing | `decode` | HMAC/RSA verification against configured key(s) only | `jwt_service_wrong_secret_fails`, proptest `jwt_wrong_secret_fails` |
| T3 | Expired token accepted | Replay | `decode` | `exp` (and `iss`) are *required* spec claims; `jsonwebtoken` rejects expired | `jwt_error_display_messages` (`Expired` path); proptest `jwt_roundtrip` with `exp = now + 3600` |
| T4 | Malformed / hostile token panics | DoS | `decode` | Errors are `Result`; arbitrary byte strings exercised | proptest `jwt_malformed_token_fails` (`\PC{1,500}`); `fuzz/fuzz_targets/fuzz_jwt_decode.rs` |
| T5 | Revoked token accepted | Replay | `decode_standard` | `jti` looked up in `TokenRevocationStore` (async) after signature validation; store errors are mapped to `Revoked` (fail-closed); in-memory store is capacity-bounded with optional TTL | `src/lib.rs::revoked_token_rejected_by_decode_standard`, `src/revocation.rs::store_never_exceeds_max_entries_and_evicts_oldest`, `src/revocation.rs::ttl_expires_entries` |
| T6 | Key rotation window breaks old tokens | Availability | `decode` with `rotation` | Decode prefers the key whose `key_id` matches the token's `kid` header; tokens without a `kid` fall back to trying every configured key | `tests/rotation.rs::kid_matching_rotation_key_verifies`, `tests/rotation.rs::no_kid_token_falls_back_to_try_all` |
| T7 | Cookie/bearer extraction mishandles hostile headers | DoS | `extract_bearer_token`, `build_auth_cookie` | Scheme/`Bearer ` prefix strip with explicit `None` on mismatch; empty token rejected | `src/lib.rs::extract_bearer_token_valid`, `extract_bearer_token_with_spaces`, `extract_bearer_token_wrong_scheme`, `extract_bearer_token_empty` |
| T8 | Cookie flags omitted → CSRF/transport exposure | Elevation | `build_auth_cookie` | Emits `HttpOnly; SameSite=Strict; Path=/` always, `Secure` when requested | `src/lib.rs::build_auth_cookie_format`, `build_auth_cookie_no_secure` |

## OPEN RISKS (missing mitigations — not fabricated)

- **OPEN-2 — no minimum secret length.** HS256 with a 2-byte secret encodes
  and decodes fine (`src/lib.rs::jwt_config_short_secret_works_for_hmac`
  proves it), and `JwtConfig::default()` carries an *empty* secret that
  `encode`/`decode` accept without error. Offline brute force of weak HMAC
  keys is trivial; there is a `JwtError::InvalidSecret` variant but no
  enforcement path pins it.
- **OPEN-3 — issuer/audience value checks are conditional.** `iss` presence
  is always required, but if `config.issuer` is `None` *any* issuer value
  passes; same for `aud`. Misconfiguration is silent.
- **OPEN-4 — tokens without `jti` bypass revocation silently.**
  `decode_standard` only consults the store `if let Some(jti)`; a caller
  issuing tokens without `jti` gets no revocation and no error.
- **OPEN-7 — JWKS cache has no fetch failure backoff.** A JWKS endpoint
  that returns errors (rather than hanging) is retried after the minimum
  refresh interval; repeated hard failures make every decode fail closed
  (availability), but there is no exponential backoff on `refresh()`.

## RESOLVED (was OPEN — fixed in this or earlier releases)

- ~~OPEN-1 — `JwtConfig` derives `Debug` and prints secrets.~~
  **RESOLVED**: manual `Debug` impls on `JwtConfig` and `RotationKey`
  redact `secret`, `der_private_key` and rotation secrets
  (`src/service.rs`); pinned by `src/lib.rs::jwt_config_debug_redacts_secret`.
- ~~OPEN-5 — `kid` header set on encode but ignored on decode.~~
  **RESOLVED** (0.3.0): `kid`-based key selection — a token whose `kid`
  matches a configured rotation key is verified only against that key;
  unknown `kid`s are rejected without a try-all fallback
  (`tests/rotation.rs::unknown_kid_rejected_without_try_all`,
  `tests/rotation.rs::kid_pin_prevents_key_confusion`).
- ~~OPEN-6 — Redis store is synchronous inside async.~~
  **RESOLVED** (0.3.0): `RedisRevocationStore` uses a multiplexed
  `redis::aio::MultiplexedConnection` (tokio) with lazy connect +
  reconnect-once retry; `decode_standard` awaits the store directly (no
  `block_in_place`/`block_on`) (`tests/revocation_redis.rs`).
- **JWKS alg-confusion surface** — **RESOLVED** (0.3.0): the JWKS decode
  path pins the token header `alg` against the JWK's `alg` member and
  rejects mismatches (`JwtError::AlgorithmMismatch`)
  (`tests/jwks_hardening.rs::jwk_alg_pinned_rejects_mismatched_token_alg`).

## Out of Scope

- Token transport after issuance (cookie theft, XSS) beyond flag emission.
- RSA key generation/rotation automation; PEMs arrive configured.
- Clock skew beyond the configurable `JwtConfig::leeway` (explicit
  default: 60s).

## Residual Risks

- Multi-secret decode widens the verification surface to all configured
  secrets simultaneously — a leaked *old* secret validates tokens until it
  is removed from `rotation_secrets`.
- `StandardClaims.role`/`permissions` are plain strings; authorization is
  entirely downstream.
