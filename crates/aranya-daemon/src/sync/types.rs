#[cfg(feature = "preview")]
use std::collections::HashMap;

#[cfg(feature = "preview")]
use tokio::time::{Duration, Instant};
#[cfg(feature = "preview")]
use tokio_util::time::delay_queue;

/// The unique identifier for a sync peer.
///
/// Contains the info needed to uniquely identify a peer:
/// - Network Address
/// - Aranya Graph ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SyncPeer {
    pub(super) addr: super::Addr,
    pub(super) graph_id: super::GraphId,
}

impl SyncPeer {
    /// Create a new `SyncPeer`.
    pub(crate) const fn new(addr: super::Addr, graph_id: super::GraphId) -> Self {
        Self { addr, graph_id }
    }
}

/// A response to a sync request.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum SyncResponse {
    /// Success.
    Ok(Box<[u8]>),
    /// Failure.
    Err(String),
}

/// Storage for a subscription to hello messages.
#[derive(Debug, Clone)]
#[cfg(feature = "preview")]
pub(crate) struct HelloSubscription {
    /// Rate limiting on how often to notify when a graph changes.
    pub(super) graph_change_debounce: Duration,
    /// The last time we notified a peer about our current graph.
    pub(super) last_notified: Option<Instant>,
    /// How far apart to space notifications on a schedule.
    pub(super) schedule_delay: Duration,
    /// How long until the subscription is no longer valid.
    pub(super) expires_at: Instant,
    /// The key to access the entry in the `DelayQueue`.
    pub(super) queue_key: delay_queue::Key,
}

/// Type alias to map a unique [`SyncPeer`] to their associated subscription.
#[cfg(feature = "preview")]
pub(crate) type HelloSubscriptions = HashMap<SyncPeer, HelloSubscription>;
