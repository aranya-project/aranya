//! Holds the [`SyncHandle`] used to send commands to the syncer.
//!
//! This uses an mpsc channel to send commands to the [`SyncManager`].
//!
//! Note that `await`ing a command will wait an arbitrary amount of time until that sync operation
//! completes and returns either success or an error.
//!
//! [`SyncManager`]: super::SyncManager
#[cfg(feature = "preview")]
use std::time::Duration;

use aranya_daemon_api::SyncPeerConfig;
#[cfg(feature = "preview")]
use aranya_runtime::Address;
use buggy::BugExt as _;
use tokio::sync::{mpsc, oneshot};

#[cfg(feature = "preview")]
use super::GraphId;
#[cfg(doc)]
use super::SyncManager;
use super::{Result, SyncPeer};

/// Holds all possible messages that the [`SyncManager`] can process.
#[derive(Clone, Debug)]
pub(crate) enum ManagerMessage {
    /// Add a peer to the [`SyncManager`]'s schedule.
    AddPeer {
        /// The unique [`SyncPeer`] to send a message to.
        peer: SyncPeer,
        /// The parameters to register the new peer with.
        cfg: SyncPeerConfig,
    },

    /// Remove a peer from the [`SyncManager`]'s schedule.
    RemovePeer {
        /// The unique [`SyncPeer`] to send a message to.
        peer: SyncPeer,
    },

    /// Sync with a peer immediately.
    SyncNow {
        /// The unique [`SyncPeer`] to send a message to.
        peer: SyncPeer,
        /// An optional config defining additional parameters.
        cfg: Option<SyncPeerConfig>,
    },

    /// Subscribe to hello notifications from a peer.
    #[cfg(feature = "preview")]
    HelloSubscribe {
        /// The unique [`SyncPeer`] to send a message to.
        peer: SyncPeer,
        /// Rate limiting on how often to notify when a graph changes.
        graph_change_delay: Duration,
        /// How long the subscription should last.
        duration: Duration,
        /// Interval to send hello notifications, regardless of graph changes.
        schedule_delay: Duration,
    },

    /// Unsubscribe from hello notifications from a peer.
    #[cfg(feature = "preview")]
    HelloUnsubscribe {
        /// The unique [`SyncPeer`] to send a message to.
        peer: SyncPeer,
    },

    /// Broadcast hello notifications to all subscribers of a graph.
    #[cfg(feature = "preview")]
    BroadcastHello {
        /// The [`GraphId`] to send a broadcast about.
        graph_id: GraphId,
        /// The current head to notify subscribers about.
        head: Address,
    },

    // === Internal Use, Sending Data From Server ===
    /// A peer has requested to subscribe to hello notifications.
    #[cfg(feature = "preview")]
    HelloSubscribeRequest {
        /// The unique [`SyncPeer`] to send a message to.
        peer: SyncPeer,
        /// Rate limiting on how often to notify when a graph changes.
        graph_change_delay: Duration,
        /// How long the subscription should last.
        duration: Duration,
        /// Interval to send hello notifications, regardless of graph changes.
        schedule_delay: Duration,
    },

    /// A peer has requested to unsubscribe from hello notifications.
    #[cfg(feature = "preview")]
    HelloUnsubscribeRequest {
        /// The unique [`SyncPeer`] to send a message to.
        peer: SyncPeer,
    },

    /// Trigger sync with a peer based on a hello message.
    #[cfg(feature = "preview")]
    SyncOnHello {
        /// The unique [`SyncPeer`] to send a message to.
        peer: SyncPeer,
        /// The current head to notify subscribers about.
        head: Address,
    },
}

/// Send messages to the [`SyncManager`] via an mpsc channel.
#[derive(Clone, Debug)]
pub(crate) struct SyncHandle {
    sender: mpsc::Sender<Callback>,
}

impl SyncHandle {
    /// Creates a new [`SyncHandle`] for sending messages.
    pub(crate) fn new(sender: mpsc::Sender<Callback>) -> Self {
        Self { sender }
    }

    /// Add a peer to the [`SyncManager`]'s schedule.
    pub(crate) async fn add_peer(&self, peer: SyncPeer, cfg: SyncPeerConfig) -> Response {
        self.send(ManagerMessage::AddPeer { peer, cfg }).await
    }

    /// Remove a peer from the [`SyncManager`]'s schedule.
    pub(crate) async fn remove_peer(&self, peer: SyncPeer) -> Response {
        self.send(ManagerMessage::RemovePeer { peer }).await
    }

    /// Sync with a peer immediately.
    pub(crate) async fn sync_now(&self, peer: SyncPeer, cfg: Option<SyncPeerConfig>) -> Response {
        self.send(ManagerMessage::SyncNow { peer, cfg }).await
    }

    /// Subscribe to hello notifications from a peer.
    #[cfg(feature = "preview")]
    pub(crate) async fn sync_hello_subscribe(
        &self,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Response {
        self.send(ManagerMessage::HelloSubscribe {
            peer,
            graph_change_delay,
            duration,
            schedule_delay,
        })
        .await
    }

    /// Unsubscribe from hello notifications from a peer.
    #[cfg(feature = "preview")]
    pub(crate) async fn sync_hello_unsubscribe(&self, peer: SyncPeer) -> Response {
        self.send(ManagerMessage::HelloUnsubscribe { peer }).await
    }

    /// Broadcast hello notifications to all subscribers of a graph.
    #[cfg(feature = "preview")]
    pub(crate) async fn broadcast_hello(&self, graph_id: GraphId, head: Address) -> Response {
        self.send(ManagerMessage::BroadcastHello { graph_id, head })
            .await
    }

    /// Tell the [`SyncManager`] to add this peer to their subscriptions.
    #[cfg(feature = "preview")]
    pub(super) async fn hello_subscribe_request(
        &self,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Response {
        self.send(ManagerMessage::HelloSubscribeRequest {
            peer,
            graph_change_delay,
            duration,
            schedule_delay,
        })
        .await
    }

    /// Tell the [`SyncManager`] to add this peer to their subscriptions.
    #[cfg(feature = "preview")]
    pub(super) async fn hello_unsubscribe_request(&self, peer: SyncPeer) -> Response {
        self.send(ManagerMessage::HelloUnsubscribeRequest { peer })
            .await
    }

    /// Trigger sync with a peer based on a hello message.
    /// Will be ignored if [`SyncPeerConfig::sync_on_hello`] is false.
    #[cfg(feature = "preview")]
    pub(super) async fn sync_on_hello(&self, peer: SyncPeer, head: Address) -> Response {
        self.send(ManagerMessage::SyncOnHello { peer, head }).await
    }

    /// Helper method for sending a message via the channel.
    async fn send(&self, msg: ManagerMessage) -> Response {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send((msg, tx))
            .await
            .assume("syncer peer channel closed")?;
        rx.await.assume("no syncer reply")?
    }
}

pub(crate) type Callback = (ManagerMessage, oneshot::Sender<Response>);
type Response = Result<()>;
