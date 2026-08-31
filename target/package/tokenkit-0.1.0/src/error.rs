use thiserror::Error;

/// Errors that can occur during JWT operations.
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("failed to encode JWT")]
    EncodingFailed,

    #[error("failed to decode JWT: {0}")]
    DecodingFailed(String),

    #[error("token has expired")]
    Expired,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("token has been revoked")]
    Revoked,

    #[error("invalid secret or key: {0}")]
    InvalidSecret(String),

    #[error("failed to load signing key: {0}")]
    KeyLoading(String),
}
