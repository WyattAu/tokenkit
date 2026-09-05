use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard JWT claims with optional extension fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StandardClaims {
    /// Subject (e.g., user ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Expiration time (UTC) — serialized as seconds since epoch for JWT compatibility.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "chrono::serde::ts_seconds_option"
    )]
    pub exp: Option<DateTime<Utc>>,

    /// Issued-at time (UTC) — serialized as seconds since epoch for JWT compatibility.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "chrono::serde::ts_seconds_option"
    )]
    pub iat: Option<DateTime<Utc>>,

    /// JWT ID (unique token identifier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// User role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,

    /// Permission list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,

    /// Additional custom claims.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}
