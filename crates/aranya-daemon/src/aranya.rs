//! This module provides the `Client` struct, which wraps an [`aranya_runtime::ClientState`]
//!
//! The `Client` is specifically designed to be shared across threads safely, using
//! an `Arc<Mutex<_>>` internally to manage concurrent access.

use std::{collections::BTreeMap, fmt, sync::Arc};

use aranya_runtime::{ClientState, PeerCache};
use derive_where::derive_where;
use tokio::sync::{Mutex, MutexGuard};

#[cfg(feature = "preview")]
use crate::sync::HelloSubscriptions;
use crate::sync::SyncPeer;

/// Thread-safe map of peer caches.
///
/// For a given peer, there should only be one cache. If separate caches are used
/// for the server and state it will reduce the efficiency of the syncer.
pub(crate) type PeerCacheMap = Arc<Mutex<BTreeMap<SyncPeer, PeerCache>>>;

mod invalid_graphs {
    use std::{collections::HashSet, sync::RwLock};

    use aranya_runtime::GraphId;

    /// Keeps track of which graphs have had a finalization error.
    ///
    /// Once a finalization error has occurred for a graph,
    /// the graph error is permanent.
    /// The API will prevent subsequent operations on the invalid graph.
    #[derive(Debug, Default)]
    pub(crate) struct InvalidGraphs {
        // NB: Since the locking is short and not held over await points,
        // we use a standard rwlock instead of tokio's.
        map: RwLock<HashSet<GraphId>>,
    }

    impl InvalidGraphs {
        pub fn insert(&self, graph_id: GraphId) {
            #[allow(clippy::expect_used)]
            self.map.write().expect("poisoned").insert(graph_id);
        }

        pub fn contains(&self, graph_id: GraphId) -> bool {
            #[allow(clippy::expect_used)]
            self.map.read().expect("poisoned").contains(&graph_id)
        }
    }
}
pub(crate) use invalid_graphs::InvalidGraphs;

/// Shared Aranya client and related state.
#[derive_where(Clone)]
pub struct Client<PS, SP> {
    /// Thread-safe Aranya client reference.
    aranya: Arc<Mutex<ClientState<PS, SP>>>,
    caches: PeerCacheMap,
    #[cfg(feature = "preview")]
    hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
    invalid_graphs: Arc<InvalidGraphs>,
}

impl<PS, SP> fmt::Debug for Client<PS, SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl<PS, SP> Client<PS, SP> {
    /// Creates a new [`Client`].
    pub fn new(aranya: ClientState<PS, SP>) -> Self {
        Self {
            aranya: Arc::new(Mutex::new(aranya)),
            caches: Arc::default(),
            #[cfg(feature = "preview")]
            hello_subscriptions: Arc::default(),
            invalid_graphs: Arc::default(),
        }
    }

    /// Lock the aranya client.
    pub async fn lock_aranya(&self) -> MutexGuard<'_, ClientState<PS, SP>> {
        self.aranya.lock().await
    }

    /// Locks both the client and caches in the correct order.
    ///
    /// This method ensures that the client (aranya) is always locked before the caches,
    /// preventing potential deadlocks. Returns a tuple of guards in the order (aranya, caches).
    pub(crate) async fn lock_aranya_and_caches(
        &self,
    ) -> (
        MutexGuard<'_, ClientState<PS, SP>>,
        MutexGuard<'_, BTreeMap<SyncPeer, PeerCache>>,
    ) {
        let aranya = self.lock_aranya().await;
        let caches = self.caches.lock().await;
        (aranya, caches)
    }

    /// Returns a reference to the hello subscriptions.
    ///
    /// Use this when you need to access or modify hello subscriptions.
    #[cfg(feature = "preview")]
    pub(crate) async fn lock_hello_subscriptions(&self) -> MutexGuard<'_, HelloSubscriptions> {
        self.hello_subscriptions.lock().await
    }

    pub(crate) fn invalid_graphs(&self) -> &InvalidGraphs {
        &self.invalid_graphs
    }

    /// Returns a clone of the peer caches Arc for test inspection.
    ///
    /// This is a test-only method to allow inspection of cache contents.
    #[cfg(test)]
    pub(crate) fn caches_for_test(&self) -> PeerCacheMap {
        Arc::clone(&self.caches)
    }
}
