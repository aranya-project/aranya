//! TODO(nikki): docs

use std::sync::Arc;

use anyhow::Context as _;
use aranya_daemon_api::TeamId;
use aranya_runtime::sync as runtime;

use super::{protocol::ProtocolStore, services::hello::HelloService, types::SyncResponse};
use crate::Addr;

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

#[async_trait::async_trait]
pub trait Handler {
    async fn handle(
        &self,
        peer: &super::SyncPeer,
        request: &[u8],
        response: &mut Vec<u8>,
    ) -> super::Result<usize>;
}

#[derive(Debug, Clone)]
pub(super) struct RequestHandler {
    protocols: Arc<ProtocolStore>,
    hello_service: Arc<HelloService>,
}

impl RequestHandler {
    fn new(protocols: Arc<ProtocolStore>, hello_service: Arc<HelloService>) -> Self {
        Self {
            protocols,
            hello_service,
        }
    }
}

#[async_trait::async_trait]
impl Handler for RequestHandler {
    async fn handle(
        &self,
        peer: &super::SyncPeer,
        request: &[u8],
        mut response: &mut Vec<u8>,
    ) -> super::Result<usize> {
        // Deserialize the wire format
        let sync_type: runtime::SyncType<Addr> =
            postcard::from_bytes(request).context("failed to deserialize sync request")?;

        match sync_type {
            runtime::SyncType::Poll {
                request: request_msg,
                address: peer_server_addr,
            } => {
                let protocol = self.protocols.get(peer);
                let mut protocol = protocol.lock().await;

                let active_team: TeamId = peer.graph_id.into_id().into();

                let response_data = protocol
                    .process_poll_request(peer.addr, peer_server_addr, request_msg, active_team)
                    .await?;

                let sync_response = SyncResponse::Ok(response_data.into());

                response.clear();
                postcard::to_io(&sync_response, &mut response)
                    .context("failed to serialize sync response")?;

                Ok(response.len())
            }
            runtime::SyncType::Hello(hello_msg) => {
                self.hello_service.handle_message(*peer, hello_msg).await?;

                response.clear();
                Ok(0)
            }
            runtime::SyncType::Subscribe { .. }
            | runtime::SyncType::Unsubscribe { .. }
            | runtime::SyncType::Push { .. } => {
                Err(anyhow::anyhow!("Push sync not implemented - use Poll + hello sync").into())
            }
        }
    }
}
