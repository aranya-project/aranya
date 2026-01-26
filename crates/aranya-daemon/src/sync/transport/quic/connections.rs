//! This module contains a map for storing persistent QUIC connections between pairs of sync peers.
//!
//! The [connection map][SharedConnectionMap] allows the sync client and server to share existing
//! connections. With mTLS authentication, a single connection can be used for syncing any team
//! since authentication is based on device certificates.

use std::{
    collections::{btree_map::Entry, BTreeMap},
    net::SocketAddr,
    sync::Arc,
};

use quinn::Connection;
use tokio::sync::{mpsc, Mutex};
use tracing::debug;

/// A [`ConnectionKey`] and [`Connection`] pair that is sent over a channel
/// when a new connection is inserted.
pub(crate) type ConnectionUpdate = (ConnectionKey, Connection);
type ConnectionMap = BTreeMap<ConnectionKey, Connection>;

/// Unique key for a connection with a peer.
///
/// With mTLS, connections are identified by peer address only since authentication
/// is based on device certificates rather than team-specific keys.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ConnectionKey {
    pub(super) addr: SocketAddr,
}

impl ConnectionKey {
    /// Creates a new connection key for the given peer address.
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

/// Thread-safe map for sharing QUIC connections between sync peers.
///
/// This map stores persistent QUIC connections indexed by [`ConnectionKey`].
#[derive(Clone, Debug)]
pub struct SharedConnectionMap {
    tx: mpsc::Sender<ConnectionUpdate>,
    connections: Arc<Mutex<ConnectionMap>>,
}

impl SharedConnectionMap {
    pub(crate) fn new() -> (Self, mpsc::Receiver<ConnectionUpdate>) {
        let (tx, rx) = mpsc::channel(32);
        (
            Self {
                tx,
                connections: Arc::default(),
            },
            rx,
        )
    }

    /// Removes a connection from the map and closes it.
    ///
    /// If the connection does not match the one in the map (by stable_id),
    /// it has been replaced and does not need to be removed.
    pub(super) async fn remove(&mut self, key: ConnectionKey, conn: Connection) {
        match self.connections.lock().await.entry(key) {
            Entry::Vacant(_) => {}
            Entry::Occupied(entry) => {
                if entry.get().stable_id() == conn.stable_id() {
                    entry.remove();
                    conn.close(0u32.into(), b"connection closed");
                }
            }
        }
    }

    /// Gets an existing connection or creates a new one using the provided closure.
    ///
    /// First checks if a connection already exists for the key. If found, verifies the connection
    /// is still open - reuses open connections and replaces closed ones. Sends a [`ConnectionUpdate`]
    /// when a new connection is created.
    ///
    /// # Parameters
    ///
    /// * `key` - The [`ConnectionKey`] that uniquely identifies the connection by peer address.
    /// * `make_conn` - Async closure that creates a new [`Connection`] when needed
    ///
    /// # Returns
    ///
    /// * `Connection` - The quinn connection (cloneable)
    ///
    /// # Errors
    ///
    /// Returns an error if the connection creation closure fails.
    pub(super) async fn get_or_try_insert_with<E>(
        &mut self,
        key: ConnectionKey,
        make_conn: impl AsyncFnOnce() -> Result<Connection, E>,
    ) -> Result<Connection, E> {
        // First, check if we have an existing usable connection
        {
            let connections = self.connections.lock().await;
            let map_size = connections.len();
            let existing_keys: Vec<_> = connections.keys().map(|k| k.addr).collect();
            debug!(
                peer = ?key.addr,
                map_size,
                existing_keys = ?existing_keys,
                "looking up connection in map"
            );

            if let Some(conn) = connections.get(&key) {
                if conn.close_reason().is_none() {
                    debug!(peer = ?key.addr, "re-using existing QUIC connection");
                    return Ok(conn.clone());
                }
                debug!(peer = ?key.addr, "existing connection is closed");
            }
        }
        // Lock is dropped here

        // Need to create a new connection
        debug!(peer = ?key.addr, "creating new QUIC connection");
        let conn = make_conn().await?;

        // Re-acquire lock and insert, handling race conditions
        let mut connections = self.connections.lock().await;
        match connections.entry(key) {
            Entry::Occupied(mut entry) => {
                // Another task may have inserted a connection while we were connecting
                if entry.get().close_reason().is_none() {
                    debug!(peer = ?key.addr, "another task inserted connection, closing ours");
                    conn.close(0u32.into(), b"duplicate connection");
                    return Ok(entry.get().clone());
                }
                // Replace the closed connection
                entry.insert(conn.clone());
            }
            Entry::Vacant(entry) => {
                entry.insert(conn.clone());
            }
        }

        debug!(peer = ?key.addr, "created new quic connection");
        self.tx.send((key, conn.clone())).await.ok();
        Ok(conn)
    }

    /// Inserts a QUIC connection into the map, unless an open connection exists.
    ///
    /// Checks if a connection already exists for the key. If found and still open,
    /// returns the original connection and closes the new one. If found but closed,
    /// replaces it with the new connection. If no connection exists, inserts the new one.
    /// Sends a [`ConnectionUpdate`] when a connection is successfully inserted.
    ///
    /// # Parameters
    ///
    /// * `key` - The [`ConnectionKey`] that uniquely identifies the connection pair
    /// * `conn` - The [`Connection`] to insert
    ///
    /// # Returns
    ///
    /// * `Connection` - The connection to use (either existing or newly inserted)
    pub(super) async fn insert(&mut self, key: ConnectionKey, conn: Connection) -> Connection {
        let (result_conn, is_new) = match self.connections.lock().await.entry(key) {
            Entry::Occupied(mut entry) => {
                debug!("existing QUIC connection found");

                // Check if connection is still open
                if entry.get().close_reason().is_none() {
                    debug!(
                        connection_key = ?key,
                        "closing new connection because an open connection was already found"
                    );
                    conn.close(0u32.into(), b"duplicate connection");
                    (entry.get().clone(), false)
                } else {
                    entry.insert(conn.clone());
                    (conn, true)
                }
            }
            Entry::Vacant(entry) => {
                debug!("existing QUIC connection not found");
                (entry.insert(conn).clone(), true)
            }
        };

        if is_new {
            debug!("created new quic connection");
            self.tx.send((key, result_conn.clone())).await.ok();
        }

        result_conn
    }
}
