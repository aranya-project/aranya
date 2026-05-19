use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use quinn::Connection;
use tokio::sync::mpsc;

use crate::sync::SyncPeer;

type ConnectionUpdate = (SyncPeer, Connection);

/// Create shared state for coordinating QUIC connections between connector and listener.
pub(super) fn pool(buffer: usize) -> (ConnectorPool, ListenerPool) {
    let (tx, rx) = mpsc::channel(buffer);
    let conns = Arc::default();
    (
        ConnectorPool {
            conns: Arc::clone(&conns),
            tx,
        },
        ListenerPool { conns, rx },
    )
}

#[derive(Debug, Default)]
pub(super) struct Conns {
    map: Mutex<BTreeMap<SyncPeer, Connection>>,
}

impl Conns {
    pub(super) fn with_map<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut BTreeMap<SyncPeer, Connection>) -> R,
    {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut map)
    }
}

#[derive(Debug)]
pub(crate) struct ConnectorPool {
    pub(super) conns: Arc<Conns>,
    pub(super) tx: mpsc::Sender<ConnectionUpdate>,
}

#[derive(Debug)]
pub(crate) struct ListenerPool {
    pub(super) conns: Arc<Conns>,
    pub(super) rx: mpsc::Receiver<ConnectionUpdate>,
}
