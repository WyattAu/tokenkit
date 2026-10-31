# Requirements: tokenkit
| REQ-TK-105 | Algorithm pinning: a token signed under any other algorithm (e.g. HS384 vs configured HS256) is rejected; the JWT algorithm-confusion defense | MUST |
  a public token identifier; not secret material.
| REQ-TK-002 | `jwt_config_short_secret_works_for_hmac` (HMAC); `jwt_config_default_is_hs256` (`src/lib.rs`). RSA arms structurally covered by `encoding_key`/`decoding_key` match arms; PEM round-trip **not** test-covered (no RSA keygen dependency); noted as residual risk | unit |
| REQ-TK-005 | `rotation_accepts_old_secret_tokens` (`src/lib.rs`); **gap test added** | unit |
| REQ-TK-101 | `expired_token_rejected` (`src/lib.rs`); **gap test added** | unit |
| REQ-TK-102 | `missing_required_claims_rejected` (`src/lib.rs`); **gap test added** | unit |
| REQ-TK-103 | `issuer_mismatch_rejected` (`src/lib.rs`); **gap test added** | unit |
| REQ-TK-104 | `audience_mismatch_rejected` (`src/lib.rs`); **gap test added** | unit |
| REQ-TK-105 | `cross_algorithm_token_rejected` (`src/lib.rs`); **gap test added** | unit |
| REQ-TK-107 | `jwt_config_debug_redacts_secret` (`src/lib.rs`); **gap test added** (regression guard for the fixed Debug leak) | unit |
| REQ-TK-110 | `revoked_token_rejected_by_decode_standard` (`src/lib.rs`); **gap test added** | unit/concurrency |
| REQ-TK-112 | `rotation_accepts_old_secret_tokens` (`src/lib.rs`); **gap test added** | unit |