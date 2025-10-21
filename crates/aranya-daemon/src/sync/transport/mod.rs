//! TODO(nikki): docs

use std::{future::Future, time::Duration};

use aranya_runtime::{Address, GraphId};

use super::Result as SyncResult;
use crate::{
    sync::{manager::SyncManager, types::SyncPeer},
    Addr,
};

pub mod quic;

/// Types that contain additional data that are part of a [`Syncer`]
/// object.
pub trait Transport: Sized {
    /// Syncs with the peer.
    ///
    /// Returns the number of commands that were received and successfully processed.
    async fn execute_sync(
        &self,
        peer: &SyncPeer,
        request: &[u8],
        response: &mut [u8],
    ) -> SyncResult<usize>;
    /*
    fn execute_sync<S>(
        syncer: &mut SyncManager<Self>,
        id: GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> impl Future<Output = SyncResult<usize>> + Send
    where
        S: Sink<<crate::EN as Engine>::Effect> + Send;
    */

    /// Subscribe to hello notifications from a sync peer.
    fn sync_hello_subscribe_impl(
        syncer: &mut SyncManager<Self>,
        id: GraphId,
        peer: &Addr,
        delay: Duration,
        duration: Duration,
    ) -> impl Future<Output = SyncResult<()>> + Send;

    /// Unsubscribe from hello notifications from a sync peer.
    fn sync_hello_unsubscribe_impl(
        syncer: &mut SyncManager<Self>,
        id: GraphId,
        peer: &Addr,
    ) -> impl Future<Output = SyncResult<()>> + Send;

    /// Broadcast hello notifications to all subscribers of a graph.
    fn broadcast_hello_notifications(
        syncer: &mut SyncManager<Self>,
        graph_id: GraphId,
        head: Address,
    ) -> impl Future<Output = SyncResult<()>> + Send;
}
