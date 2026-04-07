use std::{collections::BTreeMap, sync::Arc};

use quinn::Connection;
use tokio::sync::{mpsc, Mutex};

use crate::sync::SyncPeer;

type SharedConnectionMap = Arc<Mutex<BTreeMap<SyncPeer, Connection>>>;
type ConnectionUpdate = (SyncPeer, Connection);

/// Shared state for coordinating QUIC connections between connector and listener.
pub(super) struct ConnectionPool {
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
