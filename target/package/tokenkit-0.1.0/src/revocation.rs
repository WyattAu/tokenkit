use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for token revocation stores.
///
/// Implement this trait to provide custom revocation backends (e.g., Redis, database).
#[async_trait::async_trait]
pub trait TokenRevocationStore: Send + Sync {
    /// Revoke a token by its JWT ID.
    async fn revoke(&self, jti: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Check whether a token has been revoked.
    async fn is_revoked(&self, jti: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory token revocation store.
///
/// Suitable for single-instance applications. For distributed systems,
/// use `revocation-redis` feature or implement [`TokenRevocationStore`] yourself.
pub struct InMemoryRevocationStore {
    revoked: Arc<RwLock<HashSet<String>>>,
}

impl InMemoryRevocationStore {
    /// Create a new empty revocation store.
    pub fn new() -> Self {
        Self {
            revoked: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

impl Default for InMemoryRevocationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TokenRevocationStore for InMemoryRevocationStore {
    async fn revoke(&self, jti: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.revoked.write().await.insert(jti.to_string());
        Ok(())
    }

    async fn is_revoked(&self, jti: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.revoked.read().await.contains(jti))
    }
}

/// Redis-backed token revocation store.
///
/// Uses `SETEX` with a TTL so revoked tokens expire automatically.
/// Requires the `revocation-redis` feature.
#[cfg(feature = "revocation-redis")]
pub struct RedisRevocationStore {
    client: redis::Client,
    /// TTL in seconds for revoked token entries.
    ttl: u64,
}

#[cfg(feature = "revocation-redis")]
impl RedisRevocationStore {
    /// Create a new Redis revocation store.
    ///
    /// * `redis_url` - Redis connection string (e.g. `redis://127.0.0.1/`).
    /// * `ttl` - Time-to-live in seconds for revoked entries.
    pub fn new(redis_url: &str, ttl: u64) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self { client, ttl })
    }

    fn connection(&self) -> Result<redis::Connection, redis::RedisError> {
        self.client.get_connection()
    }
}

#[cfg(feature = "revocation-redis")]
#[async_trait::async_trait]
impl TokenRevocationStore for RedisRevocationStore {
    async fn revoke(&self, jti: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.connection()?;
        redis::cmd("SETEX")
            .arg(jti)
            .arg(self.ttl)
            .arg("1")
            .execute(&mut conn);
        Ok(())
    }

    async fn is_revoked(&self, jti: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.connection()?;
        let exists: bool = redis::cmd("EXISTS")
            .arg(jti)
            .query(&mut conn)?;
        Ok(exists)
    }
}
