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
}
