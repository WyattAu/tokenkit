#![forbid(unsafe_code)]

//! Type-safe JWT encode/decode for Rust with configurable validation,
//! secret rotation, key rotation, and revocation support.
//!
//! # Quick Start
//!
//! ```rust
//! use tokenkit::service::{JwtConfig, JwtService, JwtAlgorithm};
//! use tokenkit::claims::StandardClaims;
//!
//! let config = JwtConfig {
//!     algorithm: JwtAlgorithm::HS256,
//!     secret: "my-secret-key".to_string(),
//!     ..Default::default()
//! };
//!
//! let service = JwtService::new(config);
//! let claims = StandardClaims {
//!     sub: Some("user-123".to_string()),
//!     ..Default::default()
//! };
//!
//! let token = service.encode_standard(claims).unwrap();
//! let decoded = service.decode_standard(&token).unwrap();
//! assert_eq!(decoded.sub.as_deref(), Some("user-123"));
//! ```

pub mod claims;
pub mod error;
pub mod extractors;
pub mod service;

#[cfg(feature = "revocation")]
pub mod revocation;
