//! This module provides the `Client` struct, which wraps an [`aranya_runtime::ClientState`]
//!
//! The `Client` is specifically designed to be shared across threads safely, using
//! an `Arc<Mutex<_>>` internally to manage concurrent access.

use std::{collections::BTreeMap, fmt, sync::Arc};

use aranya_runtime::{ClientState, PeerCache};
use derive_where::derive_where;
use tokio::sync::{Mutex, MutexGuard};

use crate::sync::task::{quic::HelloSubscriptions, PeerCacheKey};

/// Thread-safe map of peer caches.
///
/// For a given peer, there should only be one cache. If separate caches are used
/// for the server and state it will reduce the efficiency of the syncer.
pub(crate) type PeerCacheMap = Arc<Mutex<BTreeMap<PeerCacheKey, PeerCache>>>;

/// Thread-safe wrapper for an Aranya client.
#[derive_where(Clone)]
pub struct Client<EN, SP> {
    /// Thread-safe Aranya client reference.
    aranya: Arc<Mutex<ClientState<EN, SP>>>,
    caches: PeerCacheMap,
    hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
}

impl<EN, SP> fmt::Debug for Client<EN, SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl<EN, SP> Client<EN, SP> {
    /// Creates a new [`Client`].
    pub fn new(aranya: ClientState<EN, SP>) -> Self {
        Self {
            aranya: Arc::new(Mutex::new(aranya)),
            caches: Arc::default(),
            hello_subscriptions: Arc::default(),
        }
    }

    /// Lock the aranya client.
    pub async fn lock_aranya(&self) -> MutexGuard<'_, ClientState<EN, SP>> {
        self.aranya.lock().await
    }

    /// Locks both the client and caches in the correct order.
    ///
    /// This method ensures that the client (aranya) is always locked before the caches,
    /// preventing potential deadlocks. Returns a tuple of guards in the order (aranya, caches).
    pub async fn lock_aranya_and_caches(
        &self,
    ) -> (
        MutexGuard<'_, ClientState<EN, SP>>,
        MutexGuard<'_, BTreeMap<PeerCacheKey, PeerCache>>,
    ) {
        let aranya = self.lock_aranya().await;
        let caches = self.caches.lock().await;
        (aranya, caches)
    }

    /// Returns a reference to the hello subscriptions.
    ///
    /// Use this when you need to access or modify hello subscriptions.
    pub async fn lock_hello_subscriptions(&self) -> MutexGuard<'_, HelloSubscriptions> {
        self.hello_subscriptions.lock().await
    }

    /// Returns a clone of the peer caches Arc for test inspection.
    ///
    /// This is a test-only method to allow inspection of cache contents.
    #[cfg(test)]
    pub(crate) fn caches_for_test(&self) -> PeerCacheMap {
        Arc::clone(&self.caches)
    }
}
