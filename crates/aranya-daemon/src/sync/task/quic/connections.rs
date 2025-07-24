//! This modules contains a map for storing persistent QUIC connections between pairs of sync peers.
//! The [connection map][SharedConnectionMap] allows the sync client and server to share existing connections by providing
//! the client access to a mutable connection [handle][Handle]. The corresponding [stream acceptor][StreamAcceptor],
//! that's used by the sync server, is sent over a channel when new connections are inserted in the map.

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
use tracing::debug;

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

/// A mutex guard that provides exclusive access to the [connection map][SharedConnectionMap]
/// with a [sender][mpsc::Sender] for sending [updates][ConnectionUpdate].
pub(super) struct MutexGuard<'a> {
    tx: mpsc::Sender<ConnectionUpdate>,
    guard: sync::MutexGuard<'a, ConnectionMap>,
}

impl MutexGuard<'_> {
    /// Removes a connection from the map and closes it.
    pub(super) async fn remove(&mut self, key: ConnectionKey) {
        if let Some(existing_conn) = self.guard.remove(&key) {
            // TODO: Use appropriate error code
            existing_conn.close(AppError::UNKNOWN);
        }
    }

    /// Gets an existing connection handle or creates a new one using the provided closure.
    ///
    /// First checks if a connection already exists for the key. If found, verifies the connection
    /// is still alive via ping - reuses open connections and replaces closed ones. Sends a [`ConnectionUpdate`] when
    /// a new connection is created. If the update cannot be sent, the newly created connection is closed.
    ///
    /// # Parameters
    ///
    /// * `key` - The [`ConnectionKey`] that uniquely identifies the connection pair
    /// * `make_conn` - Async closure that creates a new [`Connection`] when needed
    ///
    /// # Returns
    ///
    /// * `&mut Handle` - Mutable reference to the connection handle
    ///
    /// # Errors
    ///
    /// Returns an error if the connection creation closure fails or if the internal
    /// connection update channel is closed.
    pub(super) async fn get_or_try_insert_with(
        &mut self,
        key: ConnectionKey,
        make_conn: impl AsyncFnOnce() -> Result<Connection, super::Error>,
    ) -> Result<&mut Handle, super::Error> {
        let (handle, maybe_acceptor) = match self.guard.entry(key) {
            Entry::Occupied(mut entry) => {
                debug!("existing QUIC connection found");

                if entry.get_mut().ping().is_ok() {
                    debug!("re-using QUIC connection");
                    (entry.into_mut(), None)
                } else {
                    let (handle, acceptor) = make_conn().await?.split();
                    let _ = entry.insert(handle);
                    (entry.into_mut(), Some(acceptor))
                }
            }
            Entry::Vacant(entry) => {
                debug!("existing QUIC connection not found");
                let (handle, acceptor) = make_conn().await?.split();

                (entry.insert(handle), Some(acceptor))
            }
        };

        if let Some(acceptor) = maybe_acceptor {
            debug!("created new quic connection");
            Self::send(self.tx.clone(), (key, acceptor), handle)
                .await
                .map_err(Into::into)
        } else {
            Ok(handle)
        }
    }

    /// Attempts to insert a QUIC connection into the map, failing if an open connection exists.
    ///
    /// Checks if a connection already exists for the key. If found and still alive via ping,
    /// returns an error with the original connection. If found but closed, replaces it with the
    /// new connection. If no connection exists, inserts the new one. Sends a [`ConnectionUpdate`]
    /// when a connection is successfully inserted. If the update cannot be sent, the newly
    /// inserted connection is closed.
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
    /// # Errors
    ///
    /// * [`TryInsertError::Occupied`] - If an open connection already exists for the key
    /// * [`TryInsertError::ChannelClosed`] - If the internal connection update channel is closed
    pub(super) async fn try_insert(
        &mut self,
        key: ConnectionKey,
        conn: Connection,
    ) -> Result<&mut Handle, TryInsertError> {
        let (handle, acceptor) = match self.guard.entry(key) {
            Entry::Occupied(mut entry) => {
                debug!("existing QUIC connection found");

                if entry.get_mut().ping().is_ok() {
                    return Err(TryInsertError::Occupied(conn));
                } else {
                    let (handle, acceptor) = conn.split();
                    let _ = entry.insert(handle);
                    (entry.into_mut(), acceptor)
                }
            }
            Entry::Vacant(entry) => {
                debug!("existing QUIC connection not found");
                let (handle, acceptor) = conn.split();

                (entry.insert(handle), acceptor)
            }
        };

        debug!("created new quic connection");
        Self::send(self.tx.clone(), (key, acceptor), handle)
            .await
            .map_err(Into::into)
    }

    /// Sends a connection update over the channel, closing the connection on failure.
    async fn send(
        sender: mpsc::Sender<ConnectionUpdate>,
        (key, acceptor): ConnectionUpdate,
        handle: &mut Handle,
    ) -> Result<&mut Handle, ChannelClosedError> {
        let send_result = sender
            .send((key, acceptor))
            .await
            .map_err(|_| ChannelClosedError);

        match send_result {
            Ok(_) => Ok(handle),
            Err(e) => {
                // TODO: Use appropriate error code
                handle.close(AppError::UNKNOWN);

                return Err(e.into());
            }
        }
    }
}

impl<'a> Deref for MutexGuard<'a> {
    type Target = sync::MutexGuard<'a, ConnectionMap>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

/// Thread-safe map for sharing QUIC connections between sync peers.
///
/// This map stores persistent QUIC connections indexed by [`ConnectionKey`].
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

/// New connection could not be inserted into the map due to the channel being closed.
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[error("connection update channel was closed")]
pub struct ChannelClosedError;

/// The error returned by [try_insert][MutexGuard::try_insert].
#[derive(Debug, thiserror::Error)]
pub enum TryInsertError {
    #[error("Failed to a insert a new conneection into the map because an open connection already exists.")]
    Occupied(Connection),
    #[error(transparent)]
    ChannelClosed(#[from] ChannelClosedError),
}
