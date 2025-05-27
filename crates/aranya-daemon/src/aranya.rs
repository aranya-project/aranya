//! This module provides the `Client` struct, which wraps an [`aranya_runtime::ClientState`]
//!
//! The `Client` is specifically designed to be shared across threads safely, using
//! an `Arc<Mutex<_>>` internally to manage concurrent access.

use std::{fmt, ops::Deref, sync::Arc};

use aranya_runtime::ClientState;
use tokio::sync::Mutex;

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
