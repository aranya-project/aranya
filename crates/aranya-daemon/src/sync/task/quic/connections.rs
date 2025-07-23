//! This modules contains a map for storing persistent QUIC connections between pairs of sync peers.
//! Once a connection has been opened, it is shared between the QUIC syncer client and server.

use std::{
    collections::{btree_map::Entry, BTreeMap},
    ops::Deref,
};

use aranya_runtime::GraphId;
use s2n_quic::{
    application::Error as AppError,
    connection::{Handle, StreamAcceptor},
    Connection,
};
use tokio::sync::{self, mpsc, Mutex};

/// A [`ConnectionKey`] and [`StreamAcceptor`] pair that is sent over a channel
/// when a new connection is inserted.
pub(crate) type ConnectionUpdate = (ConnectionKey, StreamAcceptor);
type ConnectionMap = BTreeMap<ConnectionKey, Handle>;

/// Unique key for a connection with a peer.
/// Each team/graph is synced over a different QUIC connection so a team-specific PSK can be used.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ConnectionKey {
    pub(crate) addr: super::SocketAddr,
    pub(crate) id: GraphId,
}

pub(super) struct MutexGuard<'a> {
    tx: mpsc::Sender<ConnectionUpdate>,
    guard: sync::MutexGuard<'a, ConnectionMap>,
}

impl MutexGuard<'_> {
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
    ///
    /// # Note
    ///
    /// If an existing connection was reused, the connection that would've been inserted is closed.
    ///
    /// # Panics
    ///
    /// Panics if the internal connection update channel is closed.
    #[allow(clippy::expect_used, reason = "channel closed")]
    pub(super) async fn insert(
        &mut self,
        key: ConnectionKey,
        conn: Connection,
    ) -> Result<&mut Handle, super::Error> {
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
            self.tx
                .send((key, acceptor))
                .await
                .map_err(|_| super::Error::ChannelClosed)?;
        }

        Ok(handle)
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

impl<'a> Deref for MutexGuard<'a> {
    type Target = sync::MutexGuard<'a, ConnectionMap>;

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
    pub(super) async fn lock(&self) -> MutexGuard<'_> {
        let guard = self.data.lock().await;
        MutexGuard {
            guard,
            tx: self.tx.clone(),
        }
    }
}
