//! This module provides the `Client` struct, which wraps an [`aranya_runtime::ClientState`]
//!
//! The `Client` is specifically designed to be shared across threads safely, using
//! an `Arc<Mutex<_>>` internally to manage concurrent access.

use std::{collections::BTreeMap, fmt, ops::Deref, sync::Arc};

use aranya_runtime::{ClientState, PeerCache};
use tokio::sync::{Mutex, MutexGuard};

use crate::sync::task::{quic::HelloSubscriptions, PeerCacheKey};

/// Thread-safe wrapper for an Aranya client.
pub struct Client<EN, SP> {
    /// Thread-safe Aranya client reference.
    pub(crate) aranya: Arc<Mutex<ClientState<EN, SP>>>,
}

impl<EN, SP> Client<EN, SP> {
    /// Creates a new Client
    pub fn new(aranya: Arc<Mutex<ClientState<EN, SP>>>) -> Self {
        Client { aranya }
    }
}

impl<EN, SP> fmt::Debug for Client<EN, SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl<EN, SP> Clone for Client<EN, SP> {
    fn clone(&self) -> Self {
        Self {
            aranya: Arc::clone(&self.aranya),
        }
    }
}

impl<EN, SP> Deref for Client<EN, SP> {
    type Target = Mutex<ClientState<EN, SP>>;

    fn deref(&self) -> &Self::Target {
        &self.aranya
    }
}

/// Thread-safe map of peer caches.
///
/// For a given peer, there should only be one cache. If separate caches are used
/// for the server and state it will reduce the efficiency of the syncer.
pub(crate) type PeerCacheMap = Arc<Mutex<BTreeMap<PeerCacheKey, PeerCache>>>;

/// Wrapper that pairs an Aranya client with peer caches and hello subscriptions.
///
/// Ensures safe lock ordering by providing a method that locks both in the correct order.
/// The client must always be locked before the caches to prevent deadlocks.
pub(crate) struct ClientWithState<EN, SP> {
    client: Client<EN, SP>,
    caches: PeerCacheMap,
    hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
}

impl<EN, SP> ClientWithState<EN, SP> {
    /// Creates a new `ClientWithState`.
    pub fn new(
        client: Client<EN, SP>,
        caches: PeerCacheMap,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
    ) -> Self {
        Self {
            client,
            caches,
            hello_subscriptions,
        }
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
        let aranya = self.client.aranya.lock().await;
        let caches = self.caches.lock().await;
        (aranya, caches)
    }

    /// Returns a reference to the underlying client.
    ///
    /// Use this when you need to access the client alone without locking the caches.
    pub fn client(&self) -> &Client<EN, SP> {
        &self.client
    }

    /// Returns a reference to the hello subscriptions.
    ///
    /// Use this when you need to access or modify hello subscriptions.
    pub fn hello_subscriptions(&self) -> &Arc<Mutex<HelloSubscriptions>> {
        &self.hello_subscriptions
    }

    /// Returns a mutable reference to the underlying client.
    ///
    /// Use this when you need mutable access to the client alone without locking the caches.
    #[cfg(test)]
    pub(crate) fn client_mut(&mut self) -> &mut Client<EN, SP> {
        &mut self.client
    }

    /// Returns a clone of the peer caches Arc for test inspection.
    ///
    /// This is a test-only method to allow inspection of cache contents.
    #[cfg(test)]
    pub(crate) fn caches_for_test(&self) -> PeerCacheMap {
        Arc::clone(&self.caches)
    }
}

impl<EN, SP> fmt::Debug for ClientWithState<EN, SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientWithState").finish_non_exhaustive()
    }
}

impl<EN, SP> Clone for ClientWithState<EN, SP> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            caches: Arc::clone(&self.caches),
            hello_subscriptions: Arc::clone(&self.hello_subscriptions),
        }
    }
}
