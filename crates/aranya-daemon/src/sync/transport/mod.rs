//! TODO(nikki): docs

pub mod quic;

/// Types that contain additional data that are part of a [`Syncer`] object.
#[async_trait::async_trait]
pub trait Transport: Sized {
    /// Syncs with the peer.
    ///
    /// Returns the number of commands that were received and successfully processed.
    async fn execute_sync(
        &self,
        peer: &super::SyncPeer,
        request: &[u8],
        response: &mut [u8],
    ) -> super::Result<usize>;
}
