use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// Trait for token revocation stores.
///
/// Implement this trait to provide custom revocation backends (e.g., Redis, database).
#[async_trait::async_trait]
pub trait TokenRevocationStore: Send + Sync {
    /// Revoke a token by its JWT ID.
    async fn revoke(&self, jti: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Check whether a token has been revoked.
    async fn is_revoked(&self, jti: &str)
    -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

/// Default cap for [`InMemoryRevocationStore::new`] — bounds memory so a
/// flood of revocations cannot grow the store without limit.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

struct InMemoryInner {
    /// `jti` → insertion time (for TTL sweeps and oldest eviction).
    entries: HashMap<String, Instant>,
    /// Insertion order, for evicting the oldest entry when full.
    order: VecDeque<String>,
}

impl InMemoryInner {
    fn sweep_expired(&mut self, ttl: Option<Duration>) {
        let Some(ttl) = ttl else { return };
        let now = Instant::now();
        self.entries
            .retain(|_, inserted| now.duration_since(*inserted) < ttl);
        self.order.retain(|jti| self.entries.contains_key(jti));
    }

    fn evict_oldest_to(&mut self, max_entries: usize) {
        while self.entries.len() >= max_entries {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

/// In-memory token revocation store.
///
/// Suitable for single-instance applications. For distributed systems,
/// use `revocation-redis` feature or implement [`TokenRevocationStore`] yourself.
///
/// The store is *bounded*: it holds at most `max_entries` revocations
/// (default 100_000, see [`InMemoryRevocationStore::with_limits`]); once
/// full, the oldest entry is evicted. An optional per-entry TTL drops
/// entries lazily on lookup and eagerly (sweep) on insert. This keeps
/// allocation bounded even under a revocation flood.
///
/// # Requirements
/// REQ-TK-110, REQ-TK-113 (concurrent revoke/check safety)
pub struct InMemoryRevocationStore {
    inner: RwLock<InMemoryInner>,
    max_entries: usize,
    ttl: Option<Duration>,
}

impl InMemoryRevocationStore {
    /// Create a new empty revocation store with the default bound of
    /// [`DEFAULT_MAX_ENTRIES`] entries and no TTL.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_ENTRIES, None)
    }

    /// Create a bounded revocation store.
    ///
    /// * `max_entries` — hard cap on stored revocations; when reached, the
    ///   oldest entry is evicted on the next insert. Clamped to at least 1.
    /// * `ttl` — optional per-entry time-to-live; expired entries are
    ///   dropped on lookup and swept on insert.
    pub fn with_limits(max_entries: usize, ttl: Option<Duration>) -> Self {
        Self {
            inner: RwLock::new(InMemoryInner {
                entries: HashMap::new(),
                order: VecDeque::new(),
            }),
            max_entries: max_entries.max(1),
            ttl,
        }
    }

    /// Number of live entries (after sweeping any expired ones).
    pub async fn len(&self) -> usize {
        let mut inner = self.inner.write().await;
        inner.sweep_expired(self.ttl);
        inner.entries.len()
    }

    /// Whether the store holds no live entries.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Drop entries past their TTL and enforce the capacity bound.
    async fn make_room(&self) {
        let mut inner = self.inner.write().await;
        inner.sweep_expired(self.ttl);
        inner.evict_oldest_to(self.max_entries);
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
        self.make_room().await;
        let mut inner = self.inner.write().await;
        inner.entries.insert(jti.to_string(), Instant::now());
        inner.order.push_back(jti.to_string());
        Ok(())
    }

    async fn is_revoked(
        &self,
        jti: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let inner = self.inner.read().await;
        Ok(inner
            .entries
            .get(jti)
            .is_some_and(|inserted| match self.ttl {
                Some(ttl) => inserted.elapsed() < ttl,
                None => true,
            }))
    }
}

/// Redis-backed token revocation store.
///
/// Uses a multiplexed async connection (`redis::aio::MultiplexedConnection`,
/// tokio) instead of blocking synchronous calls, so revocation checks never
/// stall tokio worker threads. Requires the `revocation-redis` feature.
///
/// The connection is established lazily on first use and re-established
/// after a failure; every command runs with one retry over a fresh
/// connection. All errors fail closed: callers must treat them as
/// "revoked" (see `JwtService::decode_standard`).
#[cfg(feature = "revocation-redis")]
pub struct RedisRevocationStore {
    client: redis::Client,
    connection: RwLock<Option<redis::aio::MultiplexedConnection>>,
    /// TTL in seconds for revoked token entries.
    ttl: u64,
}

#[cfg(feature = "revocation-redis")]
impl RedisRevocationStore {
    /// Create a new Redis revocation store.
    ///
    /// The connection itself is opened lazily on first use (inside the
    /// async runtime), so constructing the store never blocks.
    ///
    /// * `redis_url` - Redis connection string (e.g. `redis://127.0.0.1/`).
    /// * `ttl` - Time-to-live in seconds for revoked entries.
    pub fn new(redis_url: &str, ttl: u64) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self {
            client,
            connection: RwLock::new(None),
            ttl,
        })
    }

    /// Return a live multiplexed connection, connecting (or reconnecting)
    /// if none is cached.
    async fn connection(&self) -> Result<redis::aio::MultiplexedConnection, redis::RedisError> {
        if let Some(conn) = self.connection.read().await.clone() {
            return Ok(conn);
        }
        let mut write = self.connection.write().await;
        if let Some(conn) = write.clone() {
            return Ok(conn);
        }
        let conn = self.client.get_multiplexed_async_connection().await?;
        *write = Some(conn.clone());
        Ok(conn)
    }

    /// Drop the cached connection so the next call reconnects.
    async fn reset_connection(&self) {
        *self.connection.write().await = None;
    }
}

#[cfg(feature = "revocation-redis")]
#[async_trait::async_trait]
impl TokenRevocationStore for RedisRevocationStore {
    async fn revoke(&self, jti: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.connection().await?;
        let mut cmd = redis::cmd("SETEX");
        cmd.arg(jti).arg(self.ttl).arg("1");
        let ack: Result<(), _> = cmd.query_async(&mut conn).await;
        match ack {
            Ok(()) => Ok(()),
            Err(_) => {
                // The multiplexed connection is likely dead: reconnect once
                // before surfacing the error (fail closed).
                self.reset_connection().await;
                let mut conn = self.connection().await?;
                let mut cmd = redis::cmd("SETEX");
                cmd.arg(jti).arg(self.ttl).arg("1");
                cmd.query_async::<redis::aio::MultiplexedConnection, ()>(&mut conn)
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            }
        }
    }

    async fn is_revoked(
        &self,
        jti: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.connection().await?;
        let mut cmd = redis::cmd("EXISTS");
        cmd.arg(jti);
        let exists: Result<bool, _> = cmd.query_async(&mut conn).await;
        match exists {
            Ok(exists) => Ok(exists),
            Err(_) => {
                self.reset_connection().await;
                let mut conn = self.connection().await?;
                let mut cmd = redis::cmd("EXISTS");
                cmd.arg(jti);
                cmd.query_async::<redis::aio::MultiplexedConnection, bool>(&mut conn)
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            }
        }
    }
}

// Tests exercise failure paths and invariants directly; unwrap/expect,
// slicing, and panicking asserts are acceptable here — violations surface
// as test failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    /// Bounded store: capacity is never exceeded, and the OLDEST entry is
    /// evicted first (FIFO).
    #[test]
    fn store_never_exceeds_max_entries_and_evicts_oldest() {
        let rt = runtime();
        rt.block_on(async {
            let store = InMemoryRevocationStore::with_limits(3, None);
            assert!(store.is_empty().await);

            for jti in ["jti-1", "jti-2", "jti-3"] {
                store.revoke(jti).await.unwrap();
            }
            assert_eq!(store.len().await, 3);

            // Fourth insert evicts jti-1 (the oldest), not the newest.
            store.revoke("jti-4").await.unwrap();
            assert_eq!(store.len().await, 3, "store must stay bounded");
            assert!(!store.is_revoked("jti-1").await.unwrap(), "oldest evicted");
            assert!(store.is_revoked("jti-2").await.unwrap());
            assert!(store.is_revoked("jti-3").await.unwrap());
            assert!(store.is_revoked("jti-4").await.unwrap());
        });
    }

    /// Even a flood of revocations cannot grow the store past its bound.
    #[test]
    fn flood_of_revocations_stays_bounded() {
        let rt = runtime();
        rt.block_on(async {
            let store = InMemoryRevocationStore::with_limits(50, None);
            for i in 0..500 {
                store.revoke(&format!("flood-{i}")).await.unwrap();
            }
            assert_eq!(store.len().await, 50);
            // Newest survive, oldest are gone.
            assert!(store.is_revoked("flood-499").await.unwrap());
            assert!(!store.is_revoked("flood-0").await.unwrap());
        });
    }

    /// Per-entry TTL: expired entries read as not-revoked and are dropped.
    #[test]
    fn ttl_expires_entries() {
        let rt = runtime();
        rt.block_on(async {
            let store = InMemoryRevocationStore::with_limits(100, Some(Duration::from_millis(30)));
            store.revoke("ephemeral").await.unwrap();
            assert!(store.is_revoked("ephemeral").await.unwrap());

            std::thread::sleep(Duration::from_millis(50));
            assert!(!store.is_revoked("ephemeral").await.unwrap(), "TTL expired");
            assert_eq!(store.len().await, 0, "sweep drops expired entries");
        });
    }

    /// Sweep on insert: inserting after a TTL window evicts expired
    /// entries and frees capacity for fresh ones.
    #[test]
    fn sweep_on_insert_frees_capacity() {
        let rt = runtime();
        rt.block_on(async {
            let store = InMemoryRevocationStore::with_limits(2, Some(Duration::from_millis(30)));
            store.revoke("a").await.unwrap();
            store.revoke("b").await.unwrap();
            assert_eq!(store.len().await, 2);

            std::thread::sleep(Duration::from_millis(50));
            // Without the sweep-on-insert, this insert would evict a live
            // entry; with it, the expired pair is reclaimed first.
            store.revoke("c").await.unwrap();
            assert_eq!(store.len().await, 1);
            assert!(store.is_revoked("c").await.unwrap());
            assert!(!store.is_revoked("a").await.unwrap());
            assert!(!store.is_revoked("b").await.unwrap());
        });
    }

    /// Revoking the same jti twice stays one entry.
    #[test]
    fn revoke_is_idempotent() {
        let rt = runtime();
        rt.block_on(async {
            let store = InMemoryRevocationStore::new();
            store.revoke("same").await.unwrap();
            store.revoke("same").await.unwrap();
            assert_eq!(store.len().await, 1);
            assert!(store.is_revoked("same").await.unwrap());
        });
    }

    /// A max_entries of 0 is clamped to 1 — the store always has room for
    /// at least the newest revocation.
    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let rt = runtime();
        rt.block_on(async {
            let store = InMemoryRevocationStore::with_limits(0, None);
            store.revoke("first").await.unwrap();
            store.revoke("second").await.unwrap();
            assert_eq!(store.len().await, 1);
            assert!(store.is_revoked("second").await.unwrap());
        });
    }
}
