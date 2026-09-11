use chrono::{Duration, Utc};
#[cfg(feature = "rotation")]
use jsonwebtoken::decode_header;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use uuid::Uuid;

use crate::claims::StandardClaims;
use crate::error::JwtError;

#[cfg(feature = "revocation")]
use crate::revocation::TokenRevocationStore;

/// Default validation leeway (seconds) applied when [`JwtConfig::leeway`]
/// is `None`. Matches `jsonwebtoken`'s own default, but is set explicitly
/// so the effective skew tolerance never changes silently underneath us.
pub const DEFAULT_LEEWAY_SECS: u64 = 60;

/// Claims required to be present in every token unless overridden via
/// [`JwtConfig::required_claims`].
pub const DEFAULT_REQUIRED_CLAIMS: [&str; 2] = ["exp", "iss"];

/// Default bound for [`crate::revocation::InMemoryRevocationStore`].
pub const DEFAULT_REVOCATION_MAX_ENTRIES: usize = 100_000;

/// Supported JWT algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlgorithm {
    /// HMAC-SHA256 (symmetric, 256-bit key).
    HS256,
    /// HMAC-SHA384 (symmetric, 384-bit key).
    HS384,
    /// HMAC-SHA512 (symmetric, 512-bit key).
    HS512,
    /// ECDSA over P-256 with SHA-256 (asymmetric; PKCS#8 PEM key).
    ES256,
    /// ECDSA over P-384 with SHA-384 (asymmetric; PKCS#8 PEM key).
    ES384,
    /// RSASSA-PKCS1-v1_5 with SHA-256 (asymmetric, 2048-bit key minimum).
    RS256,
    /// RSASSA-PKCS1-v1_5 with SHA-384 (asymmetric, 3072-bit key minimum).
    RS384,
    /// RSASSA-PKCS1-v1_5 with SHA-512 (asymmetric, 4096-bit key minimum).
    RS512,
    /// RSASSA-PSS with SHA-256 (asymmetric; same key material as RS256).
    PS256,
    /// RSASSA-PSS with SHA-384 (asymmetric; same key material as RS384).
    PS384,
    /// RSASSA-PSS with SHA-512 (asymmetric; same key material as RS512).
    PS512,
    /// Edwards-curve Digital Signature Algorithm over Ed25519 (asymmetric;
    /// PKCS#8 PEM or raw DER key).
    EdDSA,
}

impl From<JwtAlgorithm> for jsonwebtoken::Algorithm {
    fn from(alg: JwtAlgorithm) -> Self {
        match alg {
            JwtAlgorithm::HS256 => jsonwebtoken::Algorithm::HS256,
            JwtAlgorithm::HS384 => jsonwebtoken::Algorithm::HS384,
            JwtAlgorithm::HS512 => jsonwebtoken::Algorithm::HS512,
            JwtAlgorithm::ES256 => jsonwebtoken::Algorithm::ES256,
            JwtAlgorithm::ES384 => jsonwebtoken::Algorithm::ES384,
            JwtAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
            JwtAlgorithm::RS384 => jsonwebtoken::Algorithm::RS384,
            JwtAlgorithm::RS512 => jsonwebtoken::Algorithm::RS512,
            JwtAlgorithm::PS256 => jsonwebtoken::Algorithm::PS256,
            JwtAlgorithm::PS384 => jsonwebtoken::Algorithm::PS384,
            JwtAlgorithm::PS512 => jsonwebtoken::Algorithm::PS512,
            JwtAlgorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
        }
    }
}

/// One entry in the rotation key set: secret material plus the key id that
/// tokens signed with it carry in their `kid` header.
///
/// For asymmetric algorithms, an entry may carry its own public key
/// material (`public_key` / `der_public_key`); when absent, the config-level
/// public key is used for verification.
///
/// The secret is sensitive: `Debug` is implemented manually and redacts it.
#[derive(Clone, PartialEq, Eq)]
pub struct RotationKey {
    /// Secret material (HMAC secret or PEM-encoded private key).
    pub secret: String,
    /// Key id matching the `kid` header of tokens signed with this key.
    /// Tokens carrying this `kid` are verified only against this key.
    pub key_id: Option<String>,
    /// PEM-encoded public key used to verify tokens signed by this entry
    /// (asymmetric algorithms only).
    pub public_key: Option<String>,
    /// Raw DER public key bytes for this entry (same encodings as
    /// [`JwtConfig::der_public_key`]).
    pub der_public_key: Option<Vec<u8>>,
}

impl RotationKey {
    /// Create a rotation key from secret material and an optional key id.
    pub fn new(secret: impl Into<String>, key_id: Option<String>) -> Self {
        Self {
            secret: secret.into(),
            key_id,
            public_key: None,
            der_public_key: None,
        }
    }
}

impl std::fmt::Debug for RotationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationKey")
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .field("public_key", &self.public_key.as_ref().map(|_| "<pem>"))
            .field("der_public_key", &self.der_public_key.is_some())
            .finish()
    }
}

/// Configuration for JWT encoding and decoding.
///
/// The signing secret is sensitive: `Debug` is implemented manually and
/// redacts `secret`, `der_private_key` and `rotation_keys` so secrets
/// cannot leak through logs or diagnostics.
///
/// # Asymmetric algorithms
///
/// Signing uses the private key (`secret` / `der_private_key`);
/// verification uses the public key (`public_key` / `der_public_key`).
/// A single service that both mints and verifies tokens therefore
/// configures both. HMAC algorithms ignore the public fields and verify
/// with `secret`.
///
/// # Requirements
/// REQ-TK-107, REQ-TK-108
#[derive(Clone)]
pub struct JwtConfig {
    /// Signing algorithm.
    pub algorithm: JwtAlgorithm,
    /// Secret key (for HMAC) or PEM-encoded **private** key (for
    /// RSA/EC/EdDSA) used to sign tokens.
    pub secret: String,
    /// Raw DER (PKCS#8) private key bytes. When set, takes precedence over
    /// `secret` for signing with [`JwtAlgorithm::ES256`],
    /// [`JwtAlgorithm::ES384`] and [`JwtAlgorithm::EdDSA`]. Unused for
    /// HMAC and RSA.
    pub der_private_key: Option<Vec<u8>>,
    /// PEM-encoded **public** key used to verify tokens for asymmetric
    /// algorithms. Ignored (and unnecessary) for HMAC.
    pub public_key: Option<String>,
    /// Raw DER public key bytes — takes precedence over `public_key`.
    /// Expected encoding per family:
    ///
    /// * `RS*`/`PS*`: PKCS#1 `RSAPublicKey` DER (`SEQUENCE { n, e }`)
    /// * `ES*`: SEC1 uncompressed point (`0x04 || X || Y`)
    /// * `EdDSA`: raw public key (32 bytes for Ed25519)
    pub der_public_key: Option<Vec<u8>>,
    /// Expected issuer claim.
    pub issuer: Option<String>,
    /// Expected audience claim (single-audience convenience field; folded
    /// into [`JwtConfig::audiences`]).
    pub audience: Option<String>,
    /// All accepted audiences: a token's `aud` must be one of these.
    /// Empty means no audience validation.
    pub audiences: Vec<String>,
    /// Validation leeway in seconds for `exp`/`nbf` clock skew. `None`
    /// applies [`DEFAULT_LEEWAY_SECS`] (60) explicitly.
    pub leeway: Option<u64>,
    /// Claims that must be present in every token. Defaults to
    /// `["exp", "iss"]`.
    pub required_claims: Vec<String>,
    /// Whether to reject tokens whose `exp` has passed. Default `true`.
    pub validate_exp: bool,
    /// Whether to validate the `nbf` claim when present. Default `false`.
    pub validate_nbf: bool,
    /// Access token time-to-live in seconds.
    pub access_token_ttl: i64,
    /// Refresh token time-to-live in seconds.
    pub refresh_token_ttl: i64,
    /// Optional key ID for the current signing key (used in `kid` header).
    /// When decoding, tokens whose `kid` matches a configured key are
    /// verified only against that key.
    #[cfg(feature = "rotation")]
    pub key_id: Option<String>,
    /// Previous signing keys for rotation. Decoding prefers the key whose
    /// `key_id` matches the token's `kid` header; tokens without a `kid`
    /// header fall back to trying every configured key (legacy tokens).
    #[cfg(feature = "rotation")]
    pub rotation_keys: Vec<RotationKey>,
}

impl std::fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact secret material: the signing secret, DER key bytes, and
        // rotation secrets must never appear in Debug output (logs,
        // panics, ...).
        let mut builder = f.debug_struct("JwtConfig");
        builder
            .field("algorithm", &self.config_alg_name())
            .field("secret", &"<redacted>")
            .field(
                "der_private_key",
                &self.der_private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("public_key", &self.public_key.as_ref().map(|_| "<pem>"))
            .field("der_public_key", &self.der_public_key.is_some())
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("audiences", &self.audiences)
            .field("leeway", &self.leeway)
            .field("required_claims", &self.required_claims)
            .field("validate_exp", &self.validate_exp)
            .field("validate_nbf", &self.validate_nbf)
            .field("access_token_ttl", &self.access_token_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl);

        #[cfg(feature = "rotation")]
        {
            builder
                .field("key_id", &self.key_id)
                .field("rotation_keys", &self.rotation_keys.len());
        }

        builder.finish()
    }
}

impl JwtConfig {
    fn config_alg_name(&self) -> &'static str {
        match self.algorithm {
            JwtAlgorithm::HS256 => "HS256",
            JwtAlgorithm::HS384 => "HS384",
            JwtAlgorithm::HS512 => "HS512",
            JwtAlgorithm::ES256 => "ES256",
            JwtAlgorithm::ES384 => "ES384",
            JwtAlgorithm::RS256 => "RS256",
            JwtAlgorithm::RS384 => "RS384",
            JwtAlgorithm::RS512 => "RS512",
            JwtAlgorithm::PS256 => "PS256",
            JwtAlgorithm::PS384 => "PS384",
            JwtAlgorithm::PS512 => "PS512",
            JwtAlgorithm::EdDSA => "EdDSA",
        }
    }

    /// Create a config with rotation support, using multiple secrets.
    ///
    /// The first secret in `secrets` becomes the active signing key.
    /// Entries carry no `key_id`, so decoding falls back to trying every
    /// key (legacy behavior). Prefer [`JwtConfig::with_rotation_keys`] to
    /// get `kid`-based key selection.
    ///
    /// # Requirements
    /// REQ-TK-005, REQ-TK-112
    #[cfg(feature = "rotation")]
    pub fn with_rotation_secrets(algorithm: JwtAlgorithm, secrets: Vec<String>) -> Self {
        let keys: Vec<RotationKey> = secrets
            .into_iter()
            .map(|secret| RotationKey::new(secret, None))
            .collect();
        Self::with_rotation_keys(algorithm, keys)
    }

    /// Create a config with rotation support and `kid`-based key selection.
    ///
    /// The first key in `keys` becomes the active signing key; its
    /// `key_id` (if any) is stamped into new tokens' `kid` header. When
    /// decoding, a token whose `kid` header matches a configured key is
    /// verified only against that key; tokens without a `kid` header fall
    /// back to trying every key.
    #[cfg(feature = "rotation")]
    pub fn with_rotation_keys(algorithm: JwtAlgorithm, keys: Vec<RotationKey>) -> Self {
        let primary = keys.first().cloned().unwrap_or_else(|| RotationKey {
            secret: String::new(),
            key_id: None,
            public_key: None,
            der_public_key: None,
        });
        Self {
            algorithm,
            secret: primary.secret,
            der_private_key: None,
            public_key: None,
            der_public_key: None,
            issuer: None,
            audience: None,
            audiences: Vec::new(),
            leeway: None,
            required_claims: default_required_claims(),
            validate_exp: true,
            validate_nbf: false,
            access_token_ttl: 3600,
            refresh_token_ttl: 604800,
            key_id: primary.key_id,
            rotation_keys: keys,
        }
    }

    /// Create a config for ECDSA signing ([`JwtAlgorithm::ES256`] or
    /// [`JwtAlgorithm::ES384`]) from a PEM-encoded PKCS#8 private key.
    ///
    /// Verifying tokens additionally requires public key material — set
    /// [`JwtConfig::public_key`] (or [`JwtConfig::der_public_key`]) via
    /// [`JwtConfig::with_public_key`].
    pub fn from_ec_pem(algorithm: JwtAlgorithm, pem: impl Into<String>) -> Self {
        Self {
            algorithm,
            secret: pem.into(),
            ..Default::default()
        }
    }

    /// Create a config for [`JwtAlgorithm::EdDSA`] from a PEM-encoded
    /// PKCS#8 Ed25519 private key.
    ///
    /// Verifying tokens additionally requires public key material — set
    /// [`JwtConfig::public_key`] via [`JwtConfig::with_public_key`].
    pub fn from_ed_pem(pem: impl Into<String>) -> Self {
        Self {
            algorithm: JwtAlgorithm::EdDSA,
            secret: pem.into(),
            ..Default::default()
        }
    }

    /// Create a config for [`JwtAlgorithm::EdDSA`] from raw DER (PKCS#8)
    /// private key bytes.
    ///
    /// Verifying tokens additionally requires public key material — set
    /// [`JwtConfig::der_public_key`] (raw public key bytes) via
    /// [`JwtConfig::with_der_public_key`].
    pub fn from_ed_der(der: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm: JwtAlgorithm::EdDSA,
            der_private_key: Some(der.into()),
            ..Default::default()
        }
    }

    /// Set the PEM-encoded public key used to verify tokens for
    /// asymmetric algorithms.
    pub fn with_public_key(mut self, pem: impl Into<String>) -> Self {
        self.public_key = Some(pem.into());
        self
    }

    /// Set the raw DER public key bytes used to verify tokens for
    /// asymmetric algorithms (see [`JwtConfig::der_public_key`] for the
    /// expected encoding per algorithm family).
    pub fn with_der_public_key(mut self, der: impl Into<Vec<u8>>) -> Self {
        self.der_public_key = Some(der.into());
        self
    }

    /// Set the validation leeway (seconds) for `exp`/`nbf` clock skew.
    pub fn with_leeway(mut self, seconds: u64) -> Self {
        self.leeway = Some(seconds);
        self
    }

    /// Set the accepted audiences (multi-audience validation).
    pub fn with_audiences(mut self, audiences: Vec<String>) -> Self {
        self.audiences = audiences;
        self
    }

    /// Set the claims required to be present in every token.
    pub fn with_required_claims(mut self, claims: Vec<String>) -> Self {
        self.required_claims = claims;
        self
    }

    /// Enable or disable `exp` validation (default: enabled).
    pub fn with_validate_exp(mut self, validate: bool) -> Self {
        self.validate_exp = validate;
        self
    }

    /// Enable or disable `nbf` validation (default: disabled).
    pub fn with_validate_nbf(mut self, validate: bool) -> Self {
        self.validate_nbf = validate;
        self
    }
}

fn default_required_claims() -> Vec<String> {
    DEFAULT_REQUIRED_CLAIMS
        .iter()
        .map(|c| (*c).to_string())
        .collect()
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            algorithm: JwtAlgorithm::HS256,
            secret: String::new(),
            der_private_key: None,
            public_key: None,
            der_public_key: None,
            issuer: None,
            audience: None,
            audiences: Vec::new(),
            leeway: None,
            required_claims: default_required_claims(),
            validate_exp: true,
            validate_nbf: false,
            access_token_ttl: 3600,
            refresh_token_ttl: 604800,
            #[cfg(feature = "rotation")]
            key_id: None,
            #[cfg(feature = "rotation")]
            rotation_keys: Vec::new(),
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
    ///
    /// # Requirements
    /// REQ-TK-110
    #[cfg(feature = "revocation")]
    pub fn with_revocation(mut self, store: Box<dyn TokenRevocationStore>) -> Self {
        self.revocation = Some(store);
        self
    }

    /// Encode a custom claims struct into a JWT string.
    ///
    /// # Requirements
    /// REQ-TK-001
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

    /// Build the `jsonwebtoken` validation from this service's config.
    ///
    /// Leeway is always set explicitly (never left to the backend's hidden
    /// default), and required claims / audiences / `exp`/`nbf` toggles map
    /// 1:1 from [`JwtConfig`].
    fn build_validation(&self) -> Validation {
        let mut validation = Validation::new(self.config.algorithm.into());
        validation.leeway = self.config.leeway.unwrap_or(DEFAULT_LEEWAY_SECS);
        validation.validate_exp = self.config.validate_exp;
        validation.validate_nbf = self.config.validate_nbf;
        validation.set_required_spec_claims(self.config.required_claims.as_slice());

        if let Some(ref issuer) = self.config.issuer {
            validation.set_issuer(std::slice::from_ref(issuer));
        }

        let mut audiences = self.config.audiences.clone();
        if let Some(ref audience) = self.config.audience
            && !audiences.contains(audience)
        {
            audiences.push(audience.clone());
        }
        if !audiences.is_empty() {
            validation.set_audience(audiences.as_slice());
        }

        validation
    }

    /// Decode a JWT string into a generic claims struct.
    ///
    /// With the `rotation` feature, a token whose `kid` header matches a
    /// configured key is verified only against that key; tokens without a
    /// `kid` header fall back to trying every configured key.
    ///
    /// # Requirements
    /// REQ-TK-002, REQ-TK-100 (forged signature), REQ-TK-101 (expired),
    /// REQ-TK-102 (required claims), REQ-TK-103 (issuer), REQ-TK-104
    /// (audience), REQ-TK-105 (algorithm pinning), REQ-TK-106 (never panics
    /// on hostile input)
    pub fn decode<T: serde::de::DeserializeOwned>(&self, token: &str) -> Result<T, JwtError> {
        let validation = self.build_validation();

        #[cfg(feature = "rotation")]
        {
            self.decode_with_rotation(token, validation)
        }

        #[cfg(not(feature = "rotation"))]
        {
            let key = self.decoding_key()?;
            decode::<T>(token, &key, &validation)
                .map(|data| data.claims)
                .map_err(|e| JwtError::DecodingFailed(e.to_string()))
        }
    }

    /// Rotation-aware decode: prefer the key whose `key_id` matches the
    /// token's `kid` header (verify against that key only), and keep the
    /// try-every-key loop exclusively for legacy tokens that carry no
    /// `kid` header. A token naming an unknown `kid` is rejected without
    /// trying other keys — `kid` is attacker-controlled and must not
    /// become a key-injection oracle.
    #[cfg(feature = "rotation")]
    fn decode_with_rotation<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        validation: Validation,
    ) -> Result<T, JwtError> {
        let candidates = self.decoding_keys()?;

        if let Ok(header) = decode_header(token)
            && let Some(kid) = header.kid.as_deref()
        {
            if let Some((_, key)) = candidates.iter().find(|(k, _)| k.as_deref() == Some(kid)) {
                return decode::<T>(token, key, &validation)
                    .map(|data| data.claims)
                    .map_err(|e| JwtError::DecodingFailed(e.to_string()));
            }
            return Err(JwtError::DecodingFailed(format!(
                "token references unknown key id `{kid}`"
            )));
        }

        // Legacy tokens carry no `kid`: try every configured key.
        let mut last_err = JwtError::DecodingFailed("no keys configured".to_string());
        for (_, key) in &candidates {
            match decode::<T>(token, key, &validation) {
                Ok(data) => return Ok(data.claims),
                Err(e) => last_err = JwtError::DecodingFailed(e.to_string()),
            }
        }
        Err(last_err)
    }

    /// Encode standard claims into a JWT access token.
    ///
    /// # Requirements
    /// REQ-TK-003
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
            let mut audiences = self.config.audiences.clone();
            if let Some(ref audience) = self.config.audience
                && !audiences.contains(audience)
            {
                audiences.push(audience.clone());
            }
            claims.aud = audiences.into_iter().next();
        }
        if claims.jti.is_none() {
            claims.jti = Some(Uuid::new_v4().to_string());
        }
        self.encode(&claims)
    }

    /// Decode a JWT into standard claims, with revocation check.
    ///
    /// This is the async entry point: when a revocation store is
    /// attached, the check runs on the async store API and must be
    /// awaited from within a tokio runtime. There is deliberately no
    /// synchronous wrapper — blocking on the store from sync code stalls
    /// worker threads or panics on current-thread runtimes. Callers that
    /// cannot await should use [`JwtService::validate`] (which never
    /// checks revocation) and run revocation themselves.
    ///
    /// A revocation-store failure fails closed: the token is rejected with
    /// [`JwtError::Revoked`] rather than accepted.
    ///
    /// # Requirements
    /// REQ-TK-004, REQ-TK-110 (revocation), REQ-TK-111 (fail-closed store)
    pub async fn decode_standard(&self, token: &str) -> Result<StandardClaims, JwtError> {
        let claims: StandardClaims = self.decode(token)?;

        #[cfg(feature = "revocation")]
        if let (Some(store), Some(jti)) = (&self.revocation, &claims.jti) {
            let revoked = store.is_revoked(jti).await.map_err(|_| JwtError::Revoked)?;
            if revoked {
                return Err(JwtError::Revoked);
            }
        }

        Ok(claims)
    }

    /// Validate that a token is structurally valid and not expired.
    /// Does not perform revocation checks (and is safe to call from sync
    /// code).
    pub fn validate(&self, token: &str) -> Result<StandardClaims, JwtError> {
        self.decode::<StandardClaims>(token)
    }

    fn encoding_key(&self) -> Result<EncodingKey, JwtError> {
        encoding_key_for(
            self.config.algorithm,
            &self.config.secret,
            self.config.der_private_key.as_deref(),
        )
    }

    #[cfg(not(feature = "rotation"))]
    fn decoding_key(&self) -> Result<DecodingKey, JwtError> {
        decoding_key_for(
            self.config.algorithm,
            self.config.public_key.as_deref(),
            self.config.der_public_key.as_deref(),
            &self.config.secret,
        )
    }

    /// Build all decoding keys with their key ids: primary key first,
    /// then every rotation key.
    #[cfg(feature = "rotation")]
    fn decoding_keys(&self) -> Result<Vec<(Option<String>, DecodingKey)>, JwtError> {
        let mut keys = vec![(
            self.config.key_id.clone(),
            decoding_key_for(
                self.config.algorithm,
                self.config.public_key.as_deref(),
                self.config.der_public_key.as_deref(),
                &self.config.secret,
            )?,
        )];

        for entry in &self.config.rotation_keys {
            keys.push((
                entry.key_id.clone(),
                decoding_key_for(
                    self.config.algorithm,
                    entry
                        .public_key
                        .as_deref()
                        .or(self.config.public_key.as_deref()),
                    entry
                        .der_public_key
                        .as_deref()
                        .or(self.config.der_public_key.as_deref()),
                    &entry.secret,
                )?,
            ));
        }

        Ok(keys)
    }
}

fn key_load_error(e: impl std::fmt::Display) -> JwtError {
    JwtError::KeyLoading(e.to_string())
}

fn encoding_key_for(
    algorithm: JwtAlgorithm,
    secret: &str,
    der: Option<&[u8]>,
) -> Result<EncodingKey, JwtError> {
    match algorithm {
        JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
            Ok(EncodingKey::from_secret(secret.as_bytes()))
        }
        JwtAlgorithm::RS256
        | JwtAlgorithm::RS384
        | JwtAlgorithm::RS512
        | JwtAlgorithm::PS256
        | JwtAlgorithm::PS384
        | JwtAlgorithm::PS512 => {
            EncodingKey::from_rsa_pem(secret.as_bytes()).map_err(key_load_error)
        }
        JwtAlgorithm::ES256 | JwtAlgorithm::ES384 => {
            if let Some(der) = der {
                return Ok(EncodingKey::from_ec_der(der));
            }
            EncodingKey::from_ec_pem(secret.as_bytes()).map_err(key_load_error)
        }
        JwtAlgorithm::EdDSA => {
            if let Some(der) = der {
                return Ok(EncodingKey::from_ed_der(der));
            }
            EncodingKey::from_ed_pem(secret.as_bytes()).map_err(key_load_error)
        }
    }
}

/// Build the verification key.
///
/// * HMAC algorithms verify with the configured secret.
/// * Asymmetric algorithms verify with `public_der` / `public_pem`; when
///   neither is set, `secret` is used as a fallback — which only works
///   for decode-only configurations that store a *public* PEM in
///   `secret` (pre-0.3.0 behavior). Signing keys cannot verify: a
///   private PEM in `secret` surfaces as [`JwtError::KeyLoading`].
fn decoding_key_for(
    algorithm: JwtAlgorithm,
    public_pem: Option<&str>,
    public_der: Option<&[u8]>,
    secret: &str,
) -> Result<DecodingKey, JwtError> {
    match algorithm {
        JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
            Ok(DecodingKey::from_secret(secret.as_bytes()))
        }
        JwtAlgorithm::RS256
        | JwtAlgorithm::RS384
        | JwtAlgorithm::RS512
        | JwtAlgorithm::PS256
        | JwtAlgorithm::PS384
        | JwtAlgorithm::PS512 => {
            if let Some(der) = public_der {
                return Ok(DecodingKey::from_rsa_der(der));
            }
            let pem = public_pem.unwrap_or(secret);
            DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(key_load_error)
        }
        JwtAlgorithm::ES256 | JwtAlgorithm::ES384 => {
            if let Some(der) = public_der {
                return Ok(DecodingKey::from_ec_der(der));
            }
            let pem = public_pem.unwrap_or(secret);
            DecodingKey::from_ec_pem(pem.as_bytes()).map_err(key_load_error)
        }
        JwtAlgorithm::EdDSA => {
            if let Some(der) = public_der {
                return Ok(DecodingKey::from_ed_der(der));
            }
            let pem = public_pem.unwrap_or(secret);
            DecodingKey::from_ed_pem(pem.as_bytes()).map_err(key_load_error)
        }
    }
}
