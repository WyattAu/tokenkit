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
