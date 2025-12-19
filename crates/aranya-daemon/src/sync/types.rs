/// A sync peer.
///
/// Contains the information needed to sync with a single peer:
/// - network address
/// - Aranya graph id
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyncPeer {
    pub(crate) addr: super::Addr,
    pub(crate) graph_id: super::GraphId,
}

impl SyncPeer {
    /// Creates a new `SyncPeer`.
    pub fn new(addr: super::Addr, graph_id: super::GraphId) -> Self {
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

pub(crate) type EffectSender = tokio::sync::mpsc::Sender<(super::GraphId, Vec<crate::EF>)>;
pub(crate) type Client = crate::aranya::ClientWithState<crate::EN, crate::SP>;
