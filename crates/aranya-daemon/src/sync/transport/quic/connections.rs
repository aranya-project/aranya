use std::{collections::BTreeMap, sync::Arc};

use s2n_quic::connection::{Handle, StreamAcceptor};
use tokio::sync::{Mutex, mpsc};

use crate::sync::SyncPeer;

type SharedConnectionMap = Arc<Mutex<BTreeMap<SyncPeer, Handle>>>;
type ConnectionUpdate = (SyncPeer, StreamAcceptor);

/// Shared state for coordinating QUIC connections between connector and listener.
pub(crate) struct ConnectionPool {
    conns: SharedConnectionMap,
    tx: mpsc::Sender<ConnectionUpdate>,
    rx: mpsc::Receiver<ConnectionUpdate>,
}

impl ConnectionPool {
    pub fn new(buffer: usize) -> Self {
        let (tx, rx) = mpsc::channel(buffer);
        Self {
            conns: Arc::default(),
            tx,
            rx,
        }
    }

    pub fn split(self) -> (ConnectorPool, ListenerPool) {
        (
            ConnectorPool {
                conns: Arc::clone(&self.conns),
                tx: self.tx,
            },
            ListenerPool {
                conns: self.conns,
                rx: self.rx,
            },
        )
    }
}

#[derive(Debug)]
pub(crate) struct ConnectorPool {
    pub(super) conns: SharedConnectionMap,
    pub(super) tx: mpsc::Sender<ConnectionUpdate>,
}

#[derive(Debug)]
pub(crate) struct ListenerPool {
    pub(super) conns: SharedConnectionMap,
    pub(super) rx: mpsc::Receiver<ConnectionUpdate>,
}
