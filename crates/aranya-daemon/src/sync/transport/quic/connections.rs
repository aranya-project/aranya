//! This modules contains a map for storing persistent QUIC connections between pairs of sync peers.
//! The [connection map][SharedConnectionMap] allows the sync client and server to share existing connections by providing
//! the client access to a mutable connection [handle][Handle]. The corresponding [stream acceptor][StreamAcceptor],
//! that's used by the sync server, is sent over a channel when new connections are inserted in the map.

use std::{
    collections::{btree_map::Entry, BTreeMap},
    sync::Arc,
};

use s2n_quic::{
    application::Error as AppError,
    connection::{Handle, StreamAcceptor},
    Connection,
};
use tokio::sync::{mpsc, Mutex};
use tracing::debug;

use crate::sync::SyncPeer;

/// A [`SyncPeer`] and [`StreamAcceptor`] pair that is sent over a channel
/// when a new connection is inserted.
pub(crate) type ConnectionUpdate = (SyncPeer, StreamAcceptor);
type ConnectionMap = BTreeMap<SyncPeer, Handle>;

/// Thread-safe map for sharing QUIC connections between sync peers.
///
/// This map stores persistent QUIC connections indexed by [`SyncPeer`].
#[derive(Clone, Debug)]
pub(crate) struct SharedConnectionMap {
    tx: mpsc::Sender<ConnectionUpdate>,
    handles: Arc<Mutex<ConnectionMap>>,
}

impl SharedConnectionMap {
    pub(super) fn new() -> (Self, mpsc::Receiver<ConnectionUpdate>) {
        let (tx, rx) = mpsc::channel(32);
        (
            Self {
                tx,
                handles: Arc::default(),
            },
            rx,
        )
    }

    /// Removes a connection from the map and closes it.
    ///
    /// If the handle does not match the one in the map,
    /// it has been replaced and does not need to be removed.
    pub(super) async fn remove(&mut self, peer: SyncPeer, handle: Handle) {
        match self.handles.lock().await.entry(peer) {
            Entry::Vacant(_) => {}
            Entry::Occupied(entry) => {
                if entry.get().id() == handle.id() {
                    entry.remove();
                    handle.close(AppError::UNKNOWN);
                }
            }
        }
    }

    /// Gets an existing connection handle or creates a new one using the provided closure.
    ///
    /// First checks if a connection already exists for the key. If found, verifies the connection
    /// is still alive via ping - reuses open connections and replaces closed ones. Sends a [`ConnectionUpdate`] when
    /// a new connection is created.
    ///
    /// # Parameters
    ///
    /// * `peer` - The [`SyncPeer`] that uniquely identifies the connection pair based on team ID and the peer's network address.
    /// * `make_conn` - Async closure that creates a new [`Connection`] when needed
    ///
    /// # Returns
    ///
    /// * `Handle` - The connection handle
    ///
    /// # Errors
    ///
    /// Returns an error if the connection creation closure fails.
    pub(super) async fn get_or_try_insert_with(
        &mut self,
        peer: SyncPeer,
        make_conn: impl AsyncFnOnce() -> Result<Connection, super::Error>,
    ) -> Result<Handle, super::Error> {
        let (handle, maybe_acceptor) = match self.handles.lock().await.entry(peer) {
            Entry::Occupied(mut entry) => {
                debug!("existing QUIC connection found");

                if entry.get_mut().ping().is_ok() {
                    debug!("re-using QUIC connection");
                    (entry.get().clone(), None)
                } else {
                    let (handle, acceptor) = make_conn().await?.split();
                    let _ = entry.insert(handle);
                    (entry.get().clone(), Some(acceptor))
                }
            }
            Entry::Vacant(entry) => {
                debug!("existing QUIC connection not found");
                let (handle, acceptor) = make_conn().await?.split();

                (entry.insert(handle).clone(), Some(acceptor))
            }
        };

        if let Some(acceptor) = maybe_acceptor {
            debug!("created new quic connection");
            self.tx.send((peer, acceptor)).await.ok();
        }
        Ok(handle)
    }

    /// Inserts a QUIC connection into the map, unless an open connection exists.
    ///
    /// Checks if a connection already exists for the key. If found and still alive via ping,
    /// returns the original connection. If found but closed, replaces it with the new connection.
    /// If no connection exists, inserts the new one. Sends a [`ConnectionUpdate`] when a
    /// connection is successfully inserted.
    ///
    /// # Parameters
    ///
    /// * `peer` - The [`SyncPeer`] that uniquely identifies the connection pair
    /// * `conn` - The [`Connection`] to insert
    ///
    /// # Returns
    ///
    /// * `Handle` - The connection handle
    pub(super) async fn insert(&mut self, peer: SyncPeer, conn: Connection) -> Handle {
        let (handle, acceptor) = match self.handles.lock().await.entry(peer) {
            Entry::Occupied(mut entry) => {
                debug!("existing QUIC connection found");

                if entry.get_mut().ping().is_ok() {
                    debug!(connection_key = ?peer, "Closing the connection because an open connection was already found");
                    conn.close(AppError::UNKNOWN);
                    return entry.get().clone();
                } else {
                    let (handle, acceptor) = conn.split();
                    entry.insert(handle);
                    (entry.get().clone(), acceptor)
                }
            }
            Entry::Vacant(entry) => {
                debug!("existing QUIC connection not found");
                let (handle, acceptor) = conn.split();

                (entry.insert(handle).clone(), acceptor)
            }
        };

        debug!("created new quic connection");
        self.tx.send((peer, acceptor)).await.ok();

        handle
    }
}
