//! TODO(nikki): docs

use std::{collections::BTreeMap, sync::Arc};

use aranya_runtime::{GraphId, PeerCache};
use aranya_util::Addr;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// A sync peer.
///
/// Contains the information needed to sync with a single peer:
/// - network address
/// - Aranya graph id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SyncPeer {
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

/// Thread-safe map of peer caches.
///
/// For a given peer, there should only be one cache. If separate caches are used
/// for the server and state it will reduce the efficiency of the syncer.
pub(crate) type PeerCacheMap = Arc<Mutex<BTreeMap<SyncPeer, PeerCache>>>;

/// A response to a sync request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum SyncResponse {
    /// Success.
    Ok(Box<[u8]>),
    /// Failure.
    Err(String),
}
