use thiserror::Error;

/// Errors that can occur during JWT operations.
#[derive(Debug, Error)]
pub enum JwtError {
    /// Failed to encode the JWT token.
    #[error("failed to encode JWT")]
    EncodingFailed,

    /// Failed to decode the JWT token.
    #[error("failed to decode JWT: {0}")]
    DecodingFailed(String),

    /// The token has expired.
    #[error("token has expired")]
    Expired,

    /// The token signature is invalid.
    #[error("invalid signature")]
    InvalidSignature,

    /// The token has been revoked.
    #[error("token has been revoked")]
    Revoked,

    /// The signing secret or key is invalid.
    #[error("invalid secret or key: {0}")]
    InvalidSecret(String),

    /// Failed to load the signing key from disk.
    #[error("failed to load signing key: {0}")]
    KeyLoading(String),

    /// Failed to fetch, parse, or resolve a key from a JWKS set.
    #[error("JWKS error: {0}")]
    Jwks(String),

    /// The token's `alg` header does not match the algorithm advertised by
    /// the key (`alg` member of the JWK). This is the algorithm-confusion
    /// defense for JWKS-sourced keys: a key published for one algorithm
    /// must never verify tokens claiming another.
    #[error("algorithm mismatch: token header `{token_alg}` vs key `{key_alg}`")]
    AlgorithmMismatch {
        /// Algorithm claimed by the token header.
        token_alg: String,
        /// Algorithm advertised by the key.
        key_alg: String,
    },
}
