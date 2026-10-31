  for `JwtService::with_revocation`; revoked jti rejected with
- **`JwtService::encode_refresh_standard`**; mints refresh tokens expiring
  defaulted (604800) but **never read by any behavior**; a dead knob:
 ; all against a loopback mock JWKS endpoint with a fetch counter, no
  `async` and awaits the revocation store directly; the
  lookup); revocation floods can no longer grow memory without bound.
  60s; no longer relies on jsonwebtoken's hidden default),
  `InvalidKeyFormat`; a full sign+verify service was impossible for