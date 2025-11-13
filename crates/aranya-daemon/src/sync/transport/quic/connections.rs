use std::sync::Arc;

use dashmap::{DashMap, Entry};
use s2n_quic::{
    application::Error,
    connection::{Handle, StreamAcceptor},
    Connection,
};
use tokio::sync::mpsc;
use tracing::debug;

use super::{Result, SyncPeer};

pub(super) type ConnectionUpdate = (SyncPeer, StreamAcceptor);

/// Handles mappings betweens [`SyncPeer`]s and their associated [`Handle`].
#[derive(Debug)]
pub(super) struct SharedConnections {
    tx: mpsc::Sender<ConnectionUpdate>,
    handles: Arc<DashMap<SyncPeer, Handle>>,
}

impl SharedConnections {
    /// Create a new [`SharedConnections`].
    pub(super) fn new<const Buffer: usize>() -> (Self, mpsc::Receiver<ConnectionUpdate>) {
        let (tx, rx) = mpsc::channel(Buffer);
        (
            Self {
                tx,
                handles: Arc::default(),
            },
            rx,
        )
    }

    /// Insert a new [`Connection`] into the map.
    pub(super) async fn insert(&self, peer: SyncPeer, conn: Connection) -> Handle {
        let mut entry = self.handles.entry(peer);
        if let Entry::Occupied(ref mut entry) = entry {
            if entry.get_mut().ping().is_ok() {
                debug!("reusing existing QUIC connection, closing new connection");
                conn.close(Error::UNKNOWN);
                return entry.get().clone();
            }
        }

        let (handle, acceptor) = conn.split();
        entry.insert(handle.clone());
        debug!("created new QUIC connection");

        self.tx.send((peer, acceptor)).await.ok();
        handle
    }

    /// Get an existing [`Handle`], or try to insert a new [`Connection`] into the map.
    pub(super) async fn get_or_try_insert_with(
        &self,
        peer: SyncPeer,
        make_conn: impl AsyncFnOnce() -> Result<Connection>,
    ) -> Result<Handle> {
        let mut entry = self.handles.entry(peer);
        if let Entry::Occupied(ref mut entry) = entry {
            if entry.get_mut().ping().is_ok() {
                debug!("reusing existing QUIC connection");
                return Ok(entry.get().clone());
            }
        }

        let (handle, acceptor) = make_conn().await?.split();
        entry.insert(handle.clone());
        debug!("created new QUIC connection");

        self.tx.send((peer, acceptor)).await.ok();
        Ok(handle)
    }

    /// Remove a [`Connection`] from the map.
    pub(super) async fn remove(&self, peer: SyncPeer, handle: Handle) {
        if let Entry::Occupied(entry) = self.handles.entry(peer) {
            if entry.get().id() == handle.id() {
                entry.remove();
                handle.close(Error::UNKNOWN);
            }
        }
    }
}
