# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

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
