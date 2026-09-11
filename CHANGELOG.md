# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [0.3.0] - 2026-09-11

Security release: closes the JWKS alg-confusion surface, removes
blocking/blocking-in-async revocation paths, and bounds memory in the
in-memory revocation store.

### Security
- **JWKS algorithm pinning**: a JWK that advertises an `alg` member now
  must match the token header's `alg`; mismatches are rejected with the
  new `JwtError::AlgorithmMismatch` (HS256 token presented against an
  RS256-published key no longer reaches verification). JWKs without an
  `alg` accept only the caller's configured algorithm.
- **Async-correct revocation**: `JwtService::decode_standard` is now
  `async` and awaits the revocation store directly — the
  `block_in_place` + `block_on` wrapper (which panics on current-thread
  runtimes) is gone.
- **Redis store is async**: `RedisRevocationStore` uses a multiplexed
  `redis::aio::MultiplexedConnection` (`tokio-comp` feature) instead of
  blocking `redis::Connection` calls inside async fns; the connection is
  lazy, re-established on failure, and commands retry once (fail-closed).
- **Bounded in-memory store**: `InMemoryRevocationStore` now holds at
  most `max_entries` (default 100k, `with_limits`) with oldest-first
  eviction and an optional per-entry TTL (swept on insert, checked on
  lookup) — revocation floods can no longer grow memory without bound.

### Added
- Algorithms: `ES256`, `ES384`, `EdDSA`, `PS256`, `PS384`, `PS512` (with
  `HS*`/`RS*` now covering all twelve jsonwebtoken 11 algorithms). Key
  loaders `JwtConfig::from_ec_pem` (ES*), `from_ed_pem` (EdDSA),
  `from_ed_der`, plus builder methods `with_public_key`,
  `with_der_public_key`, `with_leeway`, `with_audiences`,
  `with_required_claims`, `with_validate_exp`, `with_validate_nbf`.
- Configurable validation on `JwtConfig`: `leeway` (explicit, default
  60s — no longer relies on jsonwebtoken's hidden default),
  `required_claims` (default `["exp", "iss"]`), multi-audience
  `audiences` (with `audience` kept as single-aud convenience, merged),
  `validate_exp` (default true), `validate_nbf` (default false).
- JWKS hardening: single-flight refresh (N concurrent misses → one
  fetch), minimum refresh interval (default 10s,
  `with_min_refresh_interval`), `JwksCache::from_static_keys` for
  air-gapped/test use.
- `kid`-based key rotation: `JwtConfig::with_rotation_keys` /
  `RotationKey` pair secrets with key ids; decoding verifies a token
  against the key its `kid` names. The try-every-key fallback applies
  only to legacy `kid`-less tokens; an unknown `kid` is rejected
  outright (no key-injection oracle).

### Changed
- **Breaking:** `decode_standard` is `async` (see Security).
- **Breaking:** `JwtConfig.rotation_secrets: Vec<String>` →
  `rotation_keys: Vec<RotationKey>` (`with_rotation_secrets` still
  exists for secret-only rotation). `RotationKey` carries an optional
  `key_id` and public key material.
- **Breaking:** asymmetric verification now uses public key material
  (`public_key` / `der_public_key`). In 0.2.0, decoding RS* tokens
  through the *private* PEM in `secret` silently failed with
  `InvalidKeyFormat` — a full sign+verify service was impossible for
  RSA. Verify side now requires public key material (HMAC unaffected;
  decode-only configs with a public PEM in `secret` keep working).
- **Breaking:** `JwtError` gained `AlgorithmMismatch` (and the config
  gained public fields), so exhaustive matches/struct literals
  downstream need updates.
- `JwksCache::decoding_key` refresh behavior: on-miss refreshes are
  single-flight and rate-limited; `refresh()` remains a forced fetch.

## [0.2.0] - 2026-09-11

### Added
- `jwks` feature: `JwksCache` fetches and caches JSON Web Key Sets with
  TTL caching and automatic re-fetch on unknown `kid` (key rotation
  without restarts).
- `JwtError::Jwks` variant for JWKS fetch/parse failures.

### Changed
- **Breaking:** `JwtError` gained the `Jwks` variant without
  `#[non_exhaustive]`, so exhaustive matches downstream need a new arm.
  Semver-checks therefore requires a major (0.x → 0.2.0) bump relative
  to the `v0.1.1` tag, whose tree predates the JWKS work.
- `jsonwebtoken` 9 → 11 (RustCrypto backend).

## [0.1.1] - 2026-09-03

### Fixed

- `StandardClaims` `exp` / `iat` now serialize as numeric timestamps
  (seconds since epoch) for JWT interoperability, instead of RFC 3339
  strings.

## [0.1.0] - 2026-08-31

### Added

- Type-safe JWT encode/decode: `StandardClaims` with serde derives,
  HS256/384/512 and RS256/384/512 algorithms.
- Built-in validation: issuer, audience, and expiration checks.
- Token revocation: pluggable `TokenRevocationStore` trait with in-memory
  and Redis-backed implementations.
- Secret & key rotation: swap `JwtConfig` without downtime; SWR caching.
- JWT helpers: `extract_bearer_token()`, `build_auth_cookie()`.
- `#![forbid(unsafe_code)]`; criterion benches, proptest suites, and
  cargo-fuzz targets (`jwt_encode` / `jwt_decode`).
