# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

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
