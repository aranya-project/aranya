//! Holds all transport traits, as well as any transport-specific implementations.

use std::future::Future;
#[cfg(feature = "preview")]
use std::time::Duration;

#[cfg(feature = "preview")]
use aranya_runtime::Address;
use aranya_runtime::{Engine, Sink};

#[cfg(feature = "preview")]
use super::GraphId;
use super::{Result, SyncManager, SyncPeer};

pub mod quic;

/// Types that contain additional data that are part of a [`SyncManager`] object.
pub(crate) trait SyncState: Sized {
    /// Syncs with the peer.
    ///
    /// Returns the number of commands that were received and successfully processed.
    fn sync_impl<S>(
        syncer: &mut SyncManager<Self>,
        peer: SyncPeer,
        sink: &mut S,
    ) -> impl Future<Output = Result<usize>> + Send
    where
        S: Sink<<crate::EN as Engine>::Effect> + Send;

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    fn sync_hello_subscribe_impl(
        syncer: &mut SyncManager<Self>,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    fn sync_hello_unsubscribe_impl(
        syncer: &mut SyncManager<Self>,
        peer: SyncPeer,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Broadcast hello notifications to all subscribers of a graph.
    #[cfg(feature = "preview")]
    fn broadcast_hello_notifications_impl(
        syncer: &mut SyncManager<Self>,
        graph_id: GraphId,
        head: Address,
    ) -> impl Future<Output = Result<()>> + Send;
}
