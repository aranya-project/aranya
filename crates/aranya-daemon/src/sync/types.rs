//! TODO(nikki): docs

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use aranya_runtime::{Address, GraphId, PeerCache};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::Addr;

/// A sync peer.
///
/// Contains the information needed to sync with a single peer:
/// - network address
/// - Aranya graph id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyncPeer {
    /// The peer address.
    pub addr: Addr,
    /// The Aranya graph ID.
    pub graph_id: GraphId,
}

impl SyncPeer {
    /// Creates a new `SyncPeer`.
    pub fn new(addr: Addr, graph_id: GraphId) -> Self {
        Self { addr, graph_id }
    }
}

/// The specific sync operation to perform.
#[derive(Debug, Clone)]
pub enum SyncType {
    /// Regular poll-based sync.
    Poll,
    /// Subscribe to hello notifications for a specific period.
    HelloSubscribe {
        /// Minimum delay between notifications.
        delay: Duration,
        /// How long the subscription should last.
        duration: Duration,
    },
    /// Unsubscribe from hello notifications.
    HelloUnsubscribe,
    /// Send a hello notification.
    HelloNotification {
        /// The new head of this peer, to update.
        head: Address,
    },
}

/// Thread-safe map of peer caches.
///
/// For a given peer, there should only be one cache. If separate caches are used
/// for the server and state it will reduce the efficiency of the syncer.
pub(crate) type PeerCacheMap = Arc<Mutex<BTreeMap<SyncPeer, PeerCache>>>;

/// A response to a sync request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SyncResponse {
    /// Success.
    Ok(Box<[u8]>),
    /// Failure.
    Err(String),
}
