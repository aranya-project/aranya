//! This module contains all generic syncer transport traits, as well as any transport-specific syncer implementations.

#[cfg(feature = "preview")]
use std::time::Duration;
use std::{fmt, future::Future};

#[cfg(feature = "preview")]
use aranya_runtime::Address;
use aranya_runtime::{PolicyStore, Sink, StorageProvider};

#[cfg(feature = "preview")]
use super::GraphId;
use super::{SyncManager, SyncPeer};

pub(crate) mod quic;

/// Types that contain additional data that are part of a [`SyncManager`] object.
pub(crate) trait SyncState<PS, SP, EF>: Sized + fmt::Debug
where
    PS: PolicyStore,
    SP: StorageProvider,
{
    /// Syncs with the peer.
    ///
    /// Returns the number of commands that were received and successfully processed.
    fn sync_impl<S: Sink<PS::Effect>>(
        syncer: &mut SyncManager<Self, PS, SP, EF>,
        peer: SyncPeer,
        sink: &mut S,
    ) -> impl Future<Output = Result<usize, super::Error>>;

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    fn sync_hello_subscribe_impl(
        syncer: &mut SyncManager<Self, PS, SP, EF>,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> impl Future<Output = Result<(), super::Error>>;

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    fn sync_hello_unsubscribe_impl(
        syncer: &mut SyncManager<Self, PS, SP, EF>,
        peer: SyncPeer,
    ) -> impl Future<Output = Result<(), super::Error>>;

    /// Broadcast hello notifications to all subscribers of a graph.
    #[cfg(feature = "preview")]
    fn broadcast_hello_notifications_impl(
        syncer: &mut SyncManager<Self, PS, SP, EF>,
        graph_id: GraphId,
        head: Address,
    ) -> impl Future<Output = Result<(), super::Error>>;
}

#[async_trait::async_trait]
pub(crate) trait SyncStream: Send + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn peer(&self) -> SyncPeer;

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    async fn receive(&mut self, buffer: &mut Vec<u8>) -> Result<(), Self::Error>;
    async fn finish(&mut self) -> Result<(), Self::Error>;
}

#[async_trait::async_trait]
pub(crate) trait SyncTransport: Send + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    type Stream: SyncStream<Error = Self::Error>;

    async fn connect(&self, peer: SyncPeer) -> Result<Self::Stream, Self::Error>;
}
