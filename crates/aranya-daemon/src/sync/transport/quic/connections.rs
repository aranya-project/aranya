use std::{collections::BTreeMap, sync::Arc};

use s2n_quic::connection::{Handle, StreamAcceptor};
use tokio::sync::{mpsc, Mutex};

use aranya_daemon_api::DeviceId;

use crate::sync::SyncPeer;

type SharedConnectionMap = Arc<Mutex<BTreeMap<SyncPeer, Handle>>>;
type ConnectionUpdate = (SyncPeer, StreamAcceptor);

/// Shared state for coordinating QUIC connections between connector and listener.
pub(crate) struct ConnectionPool {
    conns: SharedConnectionMap,
    local_device_id: DeviceId,
    tx: mpsc::Sender<ConnectionUpdate>,
    rx: mpsc::Receiver<ConnectionUpdate>,
}

impl ConnectionPool {
    pub fn new(buffer: usize, local_device_id: DeviceId) -> Self {
        let (tx, rx) = mpsc::channel(buffer);
        Self {
            conns: Arc::default(),
            local_device_id,
            tx,
            rx,
        }
    }

    pub fn split(self) -> (ConnectorPool, ListenerPool) {
        (
            ConnectorPool {
                conns: Arc::clone(&self.conns),
                local_device_id: self.local_device_id,
                tx: self.tx,
            },
            ListenerPool {
                conns: self.conns,
                local_device_id: self.local_device_id,
                rx: self.rx,
            },
        )
    }
}

#[derive(Debug)]
pub(crate) struct ConnectorPool {
    pub(super) conns: SharedConnectionMap,
    pub(super) local_device_id: DeviceId,
    pub(super) tx: mpsc::Sender<ConnectionUpdate>,
}

#[derive(Debug)]
pub(crate) struct ListenerPool {
    pub(super) conns: SharedConnectionMap,
    pub(super) local_device_id: DeviceId,
    pub(super) rx: mpsc::Receiver<ConnectionUpdate>,
}
