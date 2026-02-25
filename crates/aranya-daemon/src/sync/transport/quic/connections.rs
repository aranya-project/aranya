//! This module contains a [`SharedConnectionMap`] that allows for reusing connections for an
//! existing [`SyncPeer`].
//!
//! This works by keeping track of a connection's [`Handle`], sending the acceptor to the
//! `SyncListener` to allow it to respond when a new connection is inserted.

use std::{
    collections::{btree_map::Entry, BTreeMap},
    sync::Arc,
};

use s2n_quic::{
    application::Error as AppError,
    connection::{Handle, StreamAcceptor},
    Connection,
};
use tokio::sync::Mutex;
use tracing::debug;

use crate::sync::SyncPeer;

/// A [`SyncPeer`] and [`StreamAcceptor`] pair that is sent over a channel
/// when a new connection is inserted.
pub(crate) type ConnectionUpdate = (SyncPeer, StreamAcceptor);
type ConnectionMap = BTreeMap<SyncPeer, Handle>;

/// Thread-safe map that stores a [`Handle`] to the connection to allow for reuse across multiple
/// connection requests to a peer.
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedConnectionMap {
    /// Shared [`ConnectionMap`] to allow for cloning/shared references.
    handles: Arc<Mutex<ConnectionMap>>,
}

impl SharedConnectionMap {
    /// Creates a new [`SharedConnectionMap`].
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Tries to remove a connection from the map and close it.
    ///
    /// Note that this will skip removing it if the passed handle does not match the stored handle
    /// for the peer.
    pub(super) async fn remove(&self, peer: SyncPeer, handle: Handle) {
        match self.handles.lock().await.entry(peer) {
            Entry::Vacant(_) => {}
            Entry::Occupied(entry) => {
                // Was the handle replaced in the time the current task decided to remove it?
                if entry.get().id() == handle.id() {
                    entry.remove();
                    handle.close(AppError::UNKNOWN);
                }
            }
        }
    }

    /// Returns a handle by either getting an existing one from the map or creating a new one.
    ///
    /// If a handle already exists, we verify it's still live by pinging the peer (note that this
    /// makes no guarantees about the state of the connection after pinging it), and otherwise we
    /// create a new one and return it. If a handle doesn't already exist, we create a new one and
    /// return it.
    ///
    /// Note that the `make_conn` function can fail and return an error, but otherwise this function
    /// is infallible.
    pub(super) async fn get_or_try_insert_with(
        &self,
        peer: SyncPeer,
        make_conn: impl AsyncFnOnce() -> Result<Connection, super::Error>,
    ) -> Result<(Handle, Option<StreamAcceptor>), super::Error> {
        let mut map = self.handles.lock().await;

        match map.get_mut(&peer) {
            Some(existing) => {
                debug!("existing connection found");

                // Check if the existing handle is still alive.
                if existing.ping().is_ok() {
                    debug!("reusing the existing connection");
                    return Ok((existing.clone(), None));
                }

                // Close the handle to clean up any trailing data.
                existing.close(AppError::UNKNOWN);
            }
            None => debug!("existing connection not found"),
        }

        let (handle, acceptor) = make_conn().await?.split();
        map.insert(peer, handle.clone());
        debug!("created new quic connection");
        drop(map);

        Ok((handle, Some(acceptor)))
    }

    /// Tries to insert a connection into the map, returning the handle to it.
    ///
    /// If a handle already exists and is able to be pinged, this will close the passed connection
    /// and keep the existing one. Otherwise, it will insert the connection into the map.
    pub(super) async fn insert(
        &self,
        peer: SyncPeer,
        conn: Connection,
    ) -> (Handle, Option<StreamAcceptor>) {
        let mut map = self.handles.lock().await;

        match map.get_mut(&peer) {
            Some(existing) => {
                debug!("existing connection found");

                // Check if the existing handle is still alive.
                if existing.ping().is_ok() {
                    debug!(connection_key = ?peer, "closing the passed connection and reusing the existing one");
                    conn.close(AppError::UNKNOWN);
                    return (existing.clone(), None);
                }

                // Close the handle to clean up any trailing data.
                existing.close(AppError::UNKNOWN);
            }
            None => debug!("existing connection not found"),
        }

        let (handle, acceptor) = conn.split();
        map.insert(peer, handle.clone());
        debug!("created new connection");
        drop(map);

        (handle, Some(acceptor))
    }
}
