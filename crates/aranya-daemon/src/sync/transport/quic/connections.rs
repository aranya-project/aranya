use std::sync::Arc;

use dashmap::{DashMap, Entry};
use s2n_quic::{
    application::Error,
    connection::{Handle, StreamAcceptor},
    Connection,
};
use tokio::sync::mpsc;
use tracing::debug;

use crate::sync::SyncPeer;

type ConnectionUpdate = (SyncPeer, StreamAcceptor);

struct SharedConnections {
    tx: mpsc::Sender<ConnectionUpdate>,
    handles: Arc<DashMap<SyncPeer, Handle>>,
}

impl SharedConnections {
    fn new<const Buffer: usize>() -> (Self, mpsc::Receiver<ConnectionUpdate>) {
        let (tx, rx) = mpsc::channel(Buffer);
        (
            Self {
                tx,
                handles: Arc::default(),
            },
            rx,
        )
    }

    async fn insert(&mut self, peer: SyncPeer, conn: Connection) -> Handle {
        if let Entry::Occupied(mut entry) = self.handles.entry(peer) {
            if entry.get_mut().ping().is_ok() {
                debug!("reusing existing QUIC connection, closing new connection");
                conn.close(Error::UNKNOWN);
                return entry.get().clone();
            }
        }

        let (handle, acceptor) = conn.split();
        self.handles.entry(peer).insert(handle.clone());

        debug!("created new QUIC connection");
        self.tx.send((peer, acceptor)).await.ok();

        handle
    }

    async fn try_get_or_insert_with(
        &mut self,
        peer: SyncPeer,
        make_conn: impl AsyncFnOnce() -> Result<Connection, super::QuicError>,
    ) -> Result<Handle, super::QuicError> {
        if let Entry::Occupied(mut entry) = self.handles.entry(peer) {
            if entry.get_mut().ping().is_ok() {
                debug!("reusing existing QUIC connection");
                return Ok(entry.get().clone());
            }
        }

        let (handle, acceptor) = make_conn().await?.split();
        self.handles.entry(peer).insert(handle.clone());

        debug!("created new QUIC connection");
        self.tx.send((peer, acceptor)).await.ok();

        Ok(handle)
    }

    fn remove(&mut self, peer: SyncPeer, handle: Handle) {
        if let Entry::Occupied(entry) = self.handles.entry(peer) {
            if entry.get().id() == handle.id() {
                entry.remove();
                handle.close(Error::UNKNOWN);
            }
        }
    }
}
