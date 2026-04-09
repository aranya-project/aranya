use std::{collections::BTreeMap, sync::Arc};

use quinn::Connection;
use tokio::sync::{mpsc, Mutex};

use crate::sync::SyncPeer;

type SharedConnectionMap = Arc<Mutex<BTreeMap<SyncPeer, Connection>>>;
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
