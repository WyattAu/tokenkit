// Redis-backed revocation store must fail closed (REQ-TK-111): with no
// reachable Redis, `revoke()`/`is_revoked()` return `Err` — they must NOT
// silently succeed.
//
// Uses port 1 (tcpmux; no listener in any realistic environment) so the
// connection is refused deterministically without depending on whether a
// dev/CI Redis happens to be running on the default port.
//
// unwrap/expect are the test signal here.
#![cfg(feature = "revocation-redis")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use tokenkit::revocation::{RedisRevocationStore, TokenRevocationStore};

#[test]
fn redis_store_fails_closed_when_unreachable() {
    // No tokio "macros" feature in this crate's dep set — drive the async
    // store API through a manually built runtime.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let store = RedisRevocationStore::new("redis://127.0.0.1:1/", 60).unwrap();
        assert!(
            store.revoke("jti-unreachable").await.is_err(),
            "revoke must fail (not silently succeed) without a Redis backend"
        );
        assert!(
            store.is_revoked("jti-unreachable").await.is_err(),
            "is_revoked must fail (not silently answer) without a Redis backend"
        );
    });
}
