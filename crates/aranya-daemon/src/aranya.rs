//! This module provides the `Client` struct, which wraps an [`aranya_runtime::ClientState`]
//!
//! The `Client` is specifically designed to be shared across threads safely, using
//! an `Arc<Mutex<_>>` internally to manage concurrent access.

use std::{fmt, marker::PhantomData, sync::Arc};

use aranya_runtime::ClientState;
use tokio::sync::Mutex;

/// Thread-safe wrapper for an Aranya client.
pub struct Client<EN, SP, CE> {
    /// Thread-safe Aranya client reference.
    pub(crate) aranya: Arc<Mutex<ClientState<EN, SP>>>,
    _eng: PhantomData<CE>,
}

impl<EN, SP, CE> Client<EN, SP, CE> {
    /// Creates a new Client
    pub fn new(aranya: Arc<Mutex<ClientState<EN, SP>>>) -> Self {
        Client {
            aranya,
            _eng: PhantomData,
        }
    }
}

impl<EN, SP, CE> fmt::Debug for Client<EN, SP, CE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}
