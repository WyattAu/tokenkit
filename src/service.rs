use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::claims::StandardClaims;
use crate::error::JwtError;

#[cfg(feature = "revocation")]
use crate::revocation::TokenRevocationStore;

/// Supported JWT algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
}

impl From<JwtAlgorithm> for jsonwebtoken::Algorithm {
    fn from(alg: JwtAlgorithm) -> Self {
        match alg {
            JwtAlgorithm::HS256 => jsonwebtoken::Algorithm::HS256,
            JwtAlgorithm::HS384 => jsonwebtoken::Algorithm::HS384,
            JwtAlgorithm::HS512 => jsonwebtoken::Algorithm::HS512,
            JwtAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
            JwtAlgorithm::RS384 => jsonwebtoken::Algorithm::RS384,
            JwtAlgorithm::RS512 => jsonwebtoken::Algorithm::RS512,
        }
    }
}

/// Configuration for JWT encoding and decoding.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Signing algorithm.
    pub algorithm: JwtAlgorithm,
    /// Secret key (for HMAC) or PEM-encoded private key (for RSA).
    pub secret: String,
    /// Expected issuer claim.
    pub issuer: Option<String>,
    /// Expected audience claim.
    pub audience: Option<String>,
    /// Access token time-to-live in seconds.
    pub access_token_ttl: i64,
    /// Refresh token time-to-live in seconds.
    pub refresh_token_ttl: i64,
    /// Optional key ID for the current signing key (used in `kid` header).
    #[cfg(feature = "rotation")]
    pub key_id: Option<String>,
    /// Additional secrets for key rotation. `decode()` tries each secret
    /// until one succeeds. The first secret in this list (plus `secret`)
    /// is used for encoding.
    #[cfg(feature = "rotation")]
    pub rotation_secrets: Vec<String>,
}

impl JwtConfig {
    /// Create a config with rotation support, using multiple secrets.
    ///
    /// The first secret in `secrets` becomes the active signing key.
    /// All secrets are tried during decoding.
    #[cfg(feature = "rotation")]
    pub fn with_rotation_secrets(algorithm: JwtAlgorithm, secrets: Vec<String>) -> Self {
        let primary = secrets.first().cloned().unwrap_or_default();
        Self {
            algorithm,
            secret: primary,
            issuer: None,
            audience: None,
            access_token_ttl: 3600,
            refresh_token_ttl: 604800,
            key_id: None,
            rotation_secrets: secrets,
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            algorithm: JwtAlgorithm::HS256,
            secret: String::new(),
            issuer: None,
            audience: None,
            access_token_ttl: 3600,
            refresh_token_ttl: 604800,
            #[cfg(feature = "rotation")]
            key_id: None,
            #[cfg(feature = "rotation")]
            rotation_secrets: Vec::new(),
        }
    }
}

/// JWT service for encoding, decoding, and validating tokens.
pub struct JwtService {
    config: JwtConfig,
    #[cfg(feature = "revocation")]
    revocation: Option<Box<dyn TokenRevocationStore>>,
}

impl JwtService {
    /// Create a new JWT service with the given configuration.
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "revocation")]
            revocation: None,
        }
    }

    /// Attach a revocation store for token revocation support.
    #[cfg(feature = "revocation")]
    pub fn with_revocation(mut self, store: Box<dyn TokenRevocationStore>) -> Self {
        self.revocation = Some(store);
        self
    }

    /// Encode a custom claims struct into a JWT string.
    pub fn encode<T: serde::Serialize>(&self, claims: &T) -> Result<String, JwtError> {
        #[cfg(feature = "rotation")]
        let header = {
            let mut h = Header::new(self.config.algorithm.into());
            h.kid = self.config.key_id.clone();
            h
        };
        #[cfg(not(feature = "rotation"))]
        let header = Header::new(self.config.algorithm.into());
        let key = self.encoding_key()?;
        encode(&header, claims, &key).map_err(|_| JwtError::EncodingFailed)
    }

    /// Decode a JWT string into a generic claims struct.
    ///
    /// With the `rotation` feature, tries all configured secrets until one succeeds.
    pub fn decode<T: serde::de::DeserializeOwned>(&self, token: &str) -> Result<T, JwtError> {
        let mut validation = Validation::new(self.config.algorithm.into());
        validation.set_required_spec_claims(&["exp", "iss"]);

        if let Some(ref issuer) = self.config.issuer {
            validation.set_issuer(&[issuer.clone()]);
        }

        if let Some(ref audience) = self.config.audience {
            validation.set_audience(&[audience.clone()]);
        }

        #[cfg(feature = "rotation")]
        {
            let keys = self.decoding_keys()?;
            let mut last_err = JwtError::DecodingFailed("no keys configured".to_string());
            for key in &keys {
                match decode::<T>(token, key, &validation) {
                    Ok(data) => return Ok(data.claims),
                    Err(e) => last_err = JwtError::DecodingFailed(e.to_string()),
                }
            }
            Err(last_err)
        }

        #[cfg(not(feature = "rotation"))]
        {
            let key = self.decoding_key()?;
            decode::<T>(token, &key, &validation)
                .map(|data| data.claims)
                .map_err(|e| JwtError::DecodingFailed(e.to_string()))
        }
    }

    /// Encode standard claims into a JWT access token.
    pub fn encode_standard(&self, mut claims: StandardClaims) -> Result<String, JwtError> {
        let now = Utc::now();
        if claims.iat.is_none() {
            claims.iat = Some(now);
        }
        if claims.exp.is_none() {
            claims.exp = Some(now + Duration::seconds(self.config.access_token_ttl));
        }
        if claims.iss.is_none() {
            claims.iss = self.config.issuer.clone();
        }
        if claims.aud.is_none() {
            claims.aud = self.config.audience.clone();
        }
        if claims.jti.is_none() {
            claims.jti = Some(Uuid::new_v4().to_string());
        }
        self.encode(&claims)
    }

    /// Decode a JWT into standard claims, with optional revocation check.
    pub fn decode_standard(&self, token: &str) -> Result<StandardClaims, JwtError> {
        let claims: StandardClaims = self.decode(token)?;

        #[cfg(feature = "revocation")]
        if let (Some(store), Some(jti)) = (&self.revocation, &claims.jti) {
            let revoked = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    store.is_revoked(jti).await
                })
            })
            .map_err(|_| JwtError::Revoked)?;

            if revoked {
                return Err(JwtError::Revoked);
            }
        }

        Ok(claims)
    }

    /// Validate that a token is structurally valid and not expired.
    /// Does not perform revocation checks.
    pub fn validate(&self, token: &str) -> Result<StandardClaims, JwtError> {
        self.decode::<StandardClaims>(token)
    }

    fn encoding_key(&self) -> Result<EncodingKey, JwtError> {
        match self.config.algorithm {
            JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
                Ok(EncodingKey::from_secret(self.config.secret.as_bytes()))
            }
            JwtAlgorithm::RS256 | JwtAlgorithm::RS384 | JwtAlgorithm::RS512 => {
                EncodingKey::from_rsa_pem(self.config.secret.as_bytes())
                    .map_err(|e| JwtError::KeyLoading(e.to_string()))
            }
        }
    }

    #[cfg(not(feature = "rotation"))]
    fn decoding_key(&self) -> Result<DecodingKey, JwtError> {
        match self.config.algorithm {
            JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
                Ok(DecodingKey::from_secret(self.config.secret.as_bytes()))
            }
            JwtAlgorithm::RS256 | JwtAlgorithm::RS384 | JwtAlgorithm::RS512 => {
                DecodingKey::from_rsa_pem(self.config.secret.as_bytes())
                    .map_err(|e| JwtError::KeyLoading(e.to_string()))
            }
        }
    }

    /// Build all decoding keys: primary secret + rotation secrets.
    #[cfg(feature = "rotation")]
    fn decoding_keys(&self) -> Result<Vec<DecodingKey>, JwtError> {
        let mut all_secrets = vec![self.config.secret.clone()];
        all_secrets.extend(self.config.rotation_secrets.iter().cloned());

        all_secrets
            .into_iter()
            .map(|s| match self.config.algorithm {
                JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
                    Ok(DecodingKey::from_secret(s.as_bytes()))
                }
                JwtAlgorithm::RS256 | JwtAlgorithm::RS384 | JwtAlgorithm::RS512 => {
                    DecodingKey::from_rsa_pem(s.as_bytes())
                        .map_err(|e| JwtError::KeyLoading(e.to_string()))
                }
            })
            .collect()
    }
}
