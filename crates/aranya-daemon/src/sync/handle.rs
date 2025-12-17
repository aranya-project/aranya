#[cfg(feature = "preview")]
use std::time::Duration;

use aranya_daemon_api::SyncPeerConfig;
#[cfg(feature = "preview")]
use aranya_runtime::Address;
use buggy::BugExt as _;
use tokio::sync::{mpsc, oneshot};

use super::{GraphId, Result, SyncPeer};

/// Message sent from [`SyncHandle`] to [`Syncer`] via mpsc.
#[derive(Clone)]
pub(crate) enum ManagerMessage {
    SyncNow {
        peer: SyncPeer,
        cfg: Option<SyncPeerConfig>,
    },
    AddPeer {
        peer: SyncPeer,
        cfg: SyncPeerConfig,
    },
    RemovePeer {
        peer: SyncPeer,
    },
    #[cfg(feature = "preview")]
    HelloSubscribe {
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    },
    #[cfg(feature = "preview")]
    HelloUnsubscribe {
        peer: SyncPeer,
    },
    #[cfg(feature = "preview")]
    SyncOnHello {
        peer: SyncPeer,
    },
    #[cfg(feature = "preview")]
    BroadcastHello {
        graph_id: GraphId,
        head: Address,
    },
}

/// Handles adding and removing sync peers.
#[derive(Clone, Debug)]
pub(crate) struct SyncHandle {
    /// Send messages to add/remove peers.
    sender: mpsc::Sender<Request>,
}

impl SyncHandle {
    /// Create a new peer manager.
    pub(super) fn new(sender: mpsc::Sender<Request>) -> Self {
        Self { sender }
    }

    async fn send(&self, msg: ManagerMessage) -> Reply {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send((msg, tx))
            .await
            .assume("syncer peer channel closed")?;
        rx.await.assume("no syncer reply")?
    }

    /// Add peer to [`Syncer`].
    pub(crate) async fn add_peer(&self, peer: SyncPeer, cfg: SyncPeerConfig) -> Reply {
        self.send(ManagerMessage::AddPeer { peer, cfg }).await
    }

    /// Remove peer from [`Syncer`].
    pub(crate) async fn remove_peer(&self, peer: SyncPeer) -> Reply {
        self.send(ManagerMessage::RemovePeer { peer }).await
    }

    /// Sync with a peer immediately.
    pub(crate) async fn sync_now(&self, peer: SyncPeer, cfg: Option<SyncPeerConfig>) -> Reply {
        self.send(ManagerMessage::SyncNow { peer, cfg }).await
    }

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    pub(crate) async fn sync_hello_subscribe(
        &self,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Reply {
        self.send(ManagerMessage::HelloSubscribe {
            peer,
            graph_change_delay,
            duration,
            schedule_delay,
        })
        .await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    pub(crate) async fn sync_hello_unsubscribe(&self, peer: SyncPeer) -> Reply {
        self.send(ManagerMessage::HelloUnsubscribe { peer }).await
    }

    /// Trigger sync with a peer based on hello message.
    /// Will be ignored if `SyncPeerConfig::sync_on_hello` is false.
    #[cfg(feature = "preview")]
    pub(crate) async fn sync_on_hello(&self, peer: SyncPeer) -> Reply {
        self.send(ManagerMessage::SyncOnHello { peer }).await
    }

    /// Broadcast hello notifications to all subscribers of a graph.
    #[cfg(feature = "preview")]
    pub(crate) async fn broadcast_hello(&self, graph_id: GraphId, head: Address) -> Reply {
        self.send(ManagerMessage::BroadcastHello { graph_id, head })
            .await
    }
}

pub(crate) type Request = (ManagerMessage, oneshot::Sender<Reply>);
pub(crate) type Reply = Result<()>;
