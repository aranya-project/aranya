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
    pub(crate) fn new(addr: super::Addr, graph_id: super::GraphId) -> Self {
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
