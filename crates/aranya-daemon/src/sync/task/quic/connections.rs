//! This modules contains a map for storing persistent QUIC connections between pairs of sync peers.
//! Once a connection has been opened, it is shared between the QUIC syncer client and server.

use std::{
    collections::{btree_map::Entry, BTreeMap},
    ops::Deref,
};

use s2n_quic::{
    application::Error as AppError,
    connection::{Handle, StreamAcceptor},
    Connection,
};
use tokio::sync::{self, mpsc, Mutex};

use crate::sync::task::quic::ConnectionKey;

/// A [`ConnectionKey`] and [`StreamAcceptor`] pair that is sent over a channel
/// when a new connection is inserted.
pub(crate) type ConnectionUpdate = (ConnectionKey, StreamAcceptor);
type ConnectionMap = BTreeMap<ConnectionKey, Handle>;

pub(super) struct MutexGuard<'a, T: ?Sized> {
    tx: mpsc::Sender<ConnectionUpdate>,
    guard: sync::MutexGuard<'a, T>,
}

#[allow(clippy::expect_used, reason = "channel closed")]
impl MutexGuard<'_, ConnectionMap> {
    /// Inserts a QUIC connection into the map.
    ///
    /// Splits the connection into a handle and stream acceptor. If a connection already exists
    /// for the key, checks for open connections via ping - reuses open connections and replaces
    /// closed ones. Sends a [`ConnectionUpdate`] when a new connection is inserted.
    ///
    /// # Parameters
    ///
    /// * `key` - The [`ConnectionKey`] that uniquely identifies the connection pair
    /// * `conn` - The [`Connection`] to insert
    ///
    /// # Returns
    ///
    /// * `&mut Handle` - Mutable reference to the connection handle
    /// * `bool` - `true` if new connection was inserted, `false` if existing connection was reused
    ///
    /// # Note
    ///
    /// If an existing connection was reused, the connection that would've been inserted is closed.
    ///
    /// # Panics
    ///
    /// Panics if the internal connection update channel is closed.
    pub(super) async fn insert(
        &mut self,
        key: ConnectionKey,
        conn: Connection,
    ) -> (&mut Handle, bool) {
        let (new_handle, acceptor) = conn.split();

        let (handle, inserted) = match self.guard.entry(key) {
            Entry::Occupied(mut occupied_handle_entry) => {
                if occupied_handle_entry.get_mut().ping().is_ok() {
                    // TODO: Use appropriate error code
                    new_handle.close(AppError::UNKNOWN);

                    (occupied_handle_entry.into_mut(), false)
                } else {
                    let _ = occupied_handle_entry.insert(new_handle);
                    (occupied_handle_entry.into_mut(), true)
                }
            }
            Entry::Vacant(entry) => (entry.insert(new_handle), true),
        };

        if inserted {
            self.tx.send((key, acceptor)).await.expect("channel closed");
        }

        (handle, inserted)
    }

    pub(super) async fn remove(&mut self, key: ConnectionKey) {
        if let Some(existing_conn) = self.guard.remove(&key) {
            // TODO: Use appropriate error code
            existing_conn.close(AppError::UNKNOWN);
        }
    }

    #[inline]
    pub(super) fn get_mut(&mut self, key: &ConnectionKey) -> Option<&mut Handle> {
        self.guard.get_mut(key)
    }
}

impl<'a, T> Deref for MutexGuard<'a, T> {
    type Target = sync::MutexGuard<'a, T>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

#[derive(Debug)]
pub(crate) struct SharedConnectionMap {
    data: Mutex<BTreeMap<ConnectionKey, Handle>>,
    tx: mpsc::Sender<ConnectionUpdate>,
}

impl SharedConnectionMap {
    pub(crate) fn new() -> (Self, mpsc::Receiver<ConnectionUpdate>) {
        let (tx, rx) = mpsc::channel(32);

        (
            Self {
                data: Mutex::new(BTreeMap::new()),
                tx,
            },
            rx,
        )
    }

    #[inline]
    pub(super) async fn lock(&self) -> MutexGuard<'_, ConnectionMap> {
        let guard = self.data.lock().await;
        MutexGuard {
            guard,
            tx: self.tx.clone(),
        }
    }
}
