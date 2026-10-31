# Threat Model: tokenkit
## OPEN RISKS (missing mitigations: not fabricated)
- **OPEN-2; no minimum secret length.** HS256 with a 2-byte secret encodes
- **OPEN-3; issuer/audience value checks are conditional.** `iss` presence
- **OPEN-4; tokens without `jti` bypass revocation silently.**
- **OPEN-7; JWKS cache has no fetch failure backoff.** A JWKS endpoint
## RESOLVED (was OPEN: fixed in this or earlier releases)
- ~~OPEN-1; `JwtConfig` derives `Debug` and prints secrets.~~
- ~~OPEN-5; `kid` header set on encode but ignored on decode.~~
  **RESOLVED** (0.3.0): `kid`-based key selection; a token whose `kid`
- ~~OPEN-6; Redis store is synchronous inside async.~~
- **JWKS alg-confusion surface**; **RESOLVED** (0.3.0): the JWKS decode
  secrets simultaneously; a leaked *old* secret validates tokens until it