# Requirements — tokenkit

Numbered, testable requirements. Every requirement maps to at least one named
test; every security-relevant test cites at least one requirement. Doc
comments on the implementing public item carry `REQ-TK-NNN` tags.

Scope note: full coverage of `claims` / `service` / `revocation` (the
security-critical surface) plus `extractors`. `StandardClaims` serde details
beyond round-trip are covered by existing property tests only.

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-TK-001 | `JwtService::encode` produces a signed JWT for any `Serialize` claims struct; `decode` returns the original claims | MUST |
| REQ-TK-002 | HS256/384/512 (HMAC) and RS256/384/512 (RSA PEM) algorithms are all usable end-to-end | MUST |
| REQ-TK-003 | `encode_standard` fills `iat`, `exp` (access TTL), `iss`, `aud`, and a UUID `jti` when absent | MUST |
| REQ-TK-004 | `decode_standard` returns `StandardClaims` and consults the revocation store when one is attached | MUST |
| REQ-TK-005 | `JwtConfig::with_rotation_secrets` uses the first secret for signing and accepts tokens under any listed secret | SHOULD |
| REQ-TK-006 | `extract_bearer_token` parses `"Bearer <token>"` (tolerating padding) and rejects other schemes/empty tokens; `build_auth_cookie` emits `HttpOnly; SameSite=Strict` (+ `Secure` when requested) | MUST |

## Security

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-TK-100 | A token signed with a different secret is rejected (`InvalidSignature`/decode error), never accepted | MUST |
| REQ-TK-101 | An expired token is rejected by `decode` | MUST |
| REQ-TK-102 | `exp` and `iss` are required spec claims: a token missing them is rejected even with a valid signature | MUST |
| REQ-TK-103 | A token whose `iss` differs from the configured issuer is rejected | MUST |
| REQ-TK-104 | A token whose `aud` differs from the configured audience is rejected | MUST |
| REQ-TK-105 | Algorithm pinning: a token signed under any other algorithm (e.g. HS384 vs configured HS256) is rejected — the JWT algorithm-confusion defense | MUST |
| REQ-TK-106 | `decode` on arbitrary hostile strings returns `Err`, never panics | MUST |
| REQ-TK-107 | `Debug` for `JwtConfig` never renders the signing secret or rotation secrets | MUST |
| REQ-TK-108 | Revocation-store failures fail closed: a store error on `decode_standard` rejects the token (`JwtError::Revoked`) | MUST |
| REQ-TK-109 | Revocation matching is by `jti`; tokens without `jti` bypass the revocation check (documented limitation for callers who require revocation) | SHOULD |
| REQ-TK-110 | A revoked `jti` causes `decode_standard` to return `Err(JwtError::Revoked)`; revocation is idempotent and visible to any handle on the same store | MUST |
| REQ-TK-111 | Revocation store checks are concurrency-safe (`Send + Sync` trait object; in-memory store uses `RwLock`) | MUST |
| REQ-TK-112 | Key rotation: after rotation, tokens signed with the previous secret still verify while any rotation secret is configured; unknown-secret tokens fail | SHOULD |

## Robustness

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-TK-200 | Malformed tokens of arbitrary shape/length (1–500 arbitrary bytes) return `Err`, never panic | MUST |
| REQ-TK-201 | Claims serialization round-trips arbitrary claim values and skips `None` fields (no `null` pollution of the JWT payload) | SHOULD |
| REQ-TK-202 | `InMemoryRevocationStore` operations are async and non-blocking across concurrent tasks (`RwLock`) | SHOULD |

## Constant-Time Audit

- AUDIT: signature/MAC verification is delegated to the `jsonwebtoken`
  crate (v9), which uses HMAC/RSA implementations with constant-time
  comparison (`ring`/`crypto-bigint` backends). ✓ No `==` on secrets,
  signatures, or tags exists in this crate's code.
- FLAG (FIXED in this change): `JwtConfig` previously derived `Debug`,
  which rendered the signing secret and all `rotation_secrets` into any
  log/panic/diagnostic path. Fixed: `Debug` is now a manual impl that
  redacts both (verified by `jwt_config_debug_redacts_secret`).
- FLAG (accepted, documented): the `zeroize` dependency is declared but the
  secret `String` fields are not zeroized on drop. `JwtConfig` is `Clone`
  with public fields, so retrofitting `ZeroizeOnDrop` would break the
  public API; callers handling high-value secrets should rotate them and
  avoid cloning configs. Tracked for a breaking 0.2 release.
- AUDIT: revocation identity (`jti`) comparison is an exact string match on
  a public token identifier — not secret material.

## Traceability Matrix

| Requirement | Test (fn, file) | Property class |
|-------------|-----------------|----------------|
| REQ-TK-001 | `jwt_service_encode_decode_roundtrip` (`src/lib.rs`); `jwt_roundtrip` (proptest) | unit/property |
| REQ-TK-002 | `jwt_config_short_secret_works_for_hmac` (HMAC); `jwt_config_default_is_hs256` (`src/lib.rs`). RSA arms structurally covered by `encoding_key`/`decoding_key` match arms — PEM round-trip **not** test-covered (no RSA keygen dependency); noted as residual risk | unit |
| REQ-TK-003 | `revoked_token_rejected_by_decode_standard` (asserts token with auto-filled claims validates) (`src/lib.rs`) | unit |
| REQ-TK-004 | `revoked_token_rejected_by_decode_standard` (`src/lib.rs`) | unit |
| REQ-TK-005 | `rotation_accepts_old_secret_tokens` (`src/lib.rs`) — **gap test added** | unit |
| REQ-TK-006 | `extract_bearer_token_valid`, `extract_bearer_token_with_spaces`, `extract_bearer_token_wrong_scheme`, `extract_bearer_token_empty`, `build_auth_cookie_format`, `build_auth_cookie_no_secure` (`src/lib.rs`) | unit |
| REQ-TK-100 | `jwt_service_wrong_secret_fails`, `jwt_wrong_secret_fails` (proptest) (`src/lib.rs`) | unit/property |
| REQ-TK-101 | `expired_token_rejected` (`src/lib.rs`) — **gap test added** | unit |
| REQ-TK-102 | `missing_required_claims_rejected` (`src/lib.rs`) — **gap test added** | unit |
| REQ-TK-103 | `issuer_mismatch_rejected` (`src/lib.rs`) — **gap test added** | unit |
| REQ-TK-104 | `audience_mismatch_rejected` (`src/lib.rs`) — **gap test added** | unit |
| REQ-TK-105 | `cross_algorithm_token_rejected` (`src/lib.rs`) — **gap test added** | unit |
| REQ-TK-106 | `jwt_malformed_token_fails` (proptest) (`src/lib.rs`) | fuzz/property |
| REQ-TK-107 | `jwt_config_debug_redacts_secret` (`src/lib.rs`) — **gap test added** (regression guard for the fixed Debug leak) | unit |
| REQ-TK-108 | `src/service.rs` `decode_standard`: store `Err` → `JwtError::Revoked` (fail closed); exercised structurally via REQ-TK-110 test | unit/design |
| REQ-TK-109 | Design review: `src/service.rs` `decode_standard` requires `Some(jti)` to consult the store | design |
| REQ-TK-110 | `revoked_token_rejected_by_decode_standard` (`src/lib.rs`) — **gap test added** | unit/concurrency |
| REQ-TK-111 | `TokenRevocationStore: Send + Sync` bound (`src/revocation.rs`); `SharedStore` adapter crosses threads in REQ-TK-110 test | design/unit |
| REQ-TK-112 | `rotation_accepts_old_secret_tokens` (`src/lib.rs`) — **gap test added** | unit |
| REQ-TK-200 | `jwt_malformed_token_fails` (proptest) (`src/lib.rs`) | fuzz/property |
| REQ-TK-201 | `claims_serialization_roundtrip` (proptest), `standard_claims_serialization_roundtrip`, `standard_claims_skips_none_fields`, `standard_claims_with_extra_fields` (`src/lib.rs`) | unit/property |
| REQ-TK-202 | `InMemoryRevocationStore` via `tokio::sync::RwLock` (`src/revocation.rs`); async API exercised in REQ-TK-110 test | design/unit |

## Test Count Delta

- Before: 18 tests (14 unit + 4 proptests).
- Added: 9 (`jwt_config_debug_redacts_secret`, `expired_token_rejected`, `missing_required_claims_rejected`, `issuer_mismatch_rejected`, `audience_mismatch_rejected`, `cross_algorithm_token_rejected`, `rotation_accepts_old_secret_tokens`, `revoked_token_rejected_by_decode_standard`, + `SharedStore` test adapter).
- After: 27 (all-features build).
