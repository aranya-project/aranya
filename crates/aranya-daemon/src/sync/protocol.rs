//! Transport-independent sync protocol implementation.

use std::{sync::Arc, time::Duration};

use anyhow::Context as _;
use aranya_crypto::Rng;
use aranya_daemon_api::TeamId;
use aranya_runtime::{
    sync as runtime, Address, Command as _, PeerCache, StorageError, SyncHelloType,
    SyncRequestMessage, SyncRequester, SyncResponder, MAX_SYNC_MESSAGE_SIZE,
};
use buggy::bug;
use dashmap::DashMap;
use metrics::counter;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::{
    manager::{EffectSender, ProtocolConfig},
    types::{SyncResponse, SyncType},
    PeerCacheMap, Result, SyncPeer, Transport,
};
use crate::{vm_policy::VecSink, Addr, Client};

/// The result of a sync operation.
#[derive(Debug)]
pub enum SyncResult {
    /// The number of commands received and processed.
    CommandsProcessed(usize),
    /// Successfully handled a subscription operation.
    SubscriptionOk,
}

/// Handles Aranya sync protocol operations.
///
/// This is designed so that each peer gets a dedicated buffer to request/respond with.
#[derive(Debug)]
pub struct SyncProtocol {
    peer: SyncPeer,
    client: Client,
    caches: PeerCacheMap,
    server_addr: Addr,
    send_effects: EffectSender,
    request_buf: Vec<u8>,
    response_buf: Vec<u8>,
}

impl SyncProtocol {
    /// Create a new sync protocol handler.
    pub fn new(peer: SyncPeer, config: ProtocolConfig) -> Self {
        Self {
            peer,
            client: config.client,
            caches: config.caches,
            server_addr: config.server_addr,
            send_effects: config.send_effects,
            request_buf: vec![0; MAX_SYNC_MESSAGE_SIZE],
            response_buf: vec![0; MAX_SYNC_MESSAGE_SIZE],
        }
    }

    /// Executes a sync operation with a peer.
    pub async fn execute_sync(
        &mut self,
        transport: &impl Transport,
        sync_type: SyncType,
    ) -> Result<SyncResult> {
        let req_len: usize = match &sync_type {
            SyncType::Poll => self.build_poll_request().await?,
            SyncType::HelloSubscribe { delay, duration } => {
                self.build_hello_subscribe(*delay, *duration)?
            }
            SyncType::HelloUnsubscribe => self.build_hello_unsubscribe()?,
            SyncType::HelloNotification { head } => self.build_hello_notification(*head)?,
        };

        let resp_len = transport
            .execute_sync(
                &self.peer,
                &self.request_buf[..req_len],
                &mut self.response_buf,
            )
            .await?;

        let result = match sync_type {
            SyncType::Poll => {
                let count = self
                    .process_poll_response(&self.response_buf[..resp_len])
                    .await?;
                SyncResult::CommandsProcessed(count)
            }
            SyncType::HelloSubscribe { .. }
            | SyncType::HelloUnsubscribe
            | SyncType::HelloNotification { .. } => {
                debug!(response_len = resp_len, "received hello response");
                SyncResult::SubscriptionOk
            }
        };

        Ok(result)
    }

    /// Handle an incoming poll request.
    pub async fn process_poll_request(
        &mut self,
        peer_addr: Addr,
        peer_server_addr: Addr,
        request: SyncRequestMessage,
        active_team: TeamId,
    ) -> Result<&[u8]> {
        let storage_id = match request {
            SyncRequestMessage::SyncRequest { storage_id, .. } => storage_id,
            _ => bug!("Should be a SyncRequest"),
        };

        // TODO(nikki): verify the team_id == storage_id check?

        let mut resp = SyncResponder::new(peer_addr);
        resp.receive(request).context("sync recv failed")?;

        let len = {
            let mut aranya = self.client.aranya.lock().await;
            let peer = SyncPeer::new(peer_server_addr, storage_id);
            let mut cache = self.caches.entry(peer).or_insert_with(PeerCache::default);

            resp.poll(&mut self.response_buf, aranya.provider(), &mut cache)
                .or_else(|err| {
                    if matches!(
                        err,
                        aranya_runtime::SyncError::Storage(StorageError::NoSuchStorage)
                    ) {
                        warn!(team = %active_team, "missing requested graph");
                        Ok(0)
                    } else {
                        Err(err)
                    }
                })
                .context("sync resp poll failed")?
        };
        debug!(len = len, "sync poll finished");
        Ok(&self.response_buf[..len])
    }

    async fn process_poll_response(&self, response_data: &[u8]) -> Result<usize> {
        // Check for empty response (which indicates a hello message response)
        if response_data.is_empty() {
            debug!("received empty response, likely from hello message - ignoring");
            return Ok(0);
        }

        // process the sync response.
        let resp = postcard::from_bytes(&response_data)
            .context("postcard unable to deserialize sync response")?;
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => return Err(anyhow::anyhow!("sync error: {msg}").into()),
        };

        if data.is_empty() {
            debug!("nothing to sync");
            return Ok(0);
        }

        let graph_id = self.peer.graph_id;
        let addr = self.peer.addr;
        let mut sync_requester = SyncRequester::new(graph_id, &mut Rng, addr);
        let cmds = match sync_requester.receive(&data)? {
            Some(cmds) => cmds,
            None => return Ok(0),
        };

        if cmds.is_empty() {
            return Ok(0);
        }

        debug!(num = cmds.len(), "received commands from peer");

        let mut sink = VecSink::new();
        let mut aranya = self.client.aranya.lock().await;
        let mut trx = aranya.transaction(graph_id);
        aranya
            .add_commands(&mut trx, &mut sink, &cmds)
            .context("unable to add received commands")?;
        aranya
            .commit(&mut trx, &mut sink)
            .context("commit failed")?;

        let mut cache = self
            .caches
            .entry(self.peer.clone())
            .or_insert_with(PeerCache::default);

        aranya
            .update_heads(
                graph_id,
                cmds.iter().filter_map(|cmd| cmd.address().ok()),
                &mut cache,
            )
            .context("failed to update cache heads")?;

        let effects = sink
            .collect()
            .context("could not collect effects from sync")?;
        if !effects.is_empty() {
            counter!("sync.effects_sent").increment(effects.len() as u64);

            if let Err(e) = self.send_effects.send((graph_id, effects)).await {
                warn!(peer = %addr, graph = %graph_id, error = %e, "failed to send effects");
            }
        }

        Ok(cmds.len())
    }

    async fn build_poll_request(&mut self) -> Result<usize> {
        let mut sync_requester = SyncRequester::new(self.peer.graph_id, &mut Rng, self.server_addr);

        let len = {
            let mut aranya = self.client.aranya.lock().await;
            let mut cache = self
                .caches
                .entry(self.peer.clone())
                .or_insert_with(PeerCache::default);

            let (len, _) = sync_requester
                .poll(&mut self.request_buf, aranya.provider(), &mut cache)
                .context("sync poll failed")?;
            len
        };
        debug!(len = len, "sync poll finished");
        Ok(len)
    }

    fn build_hello_subscribe(&mut self, delay: Duration, duration: Duration) -> Result<usize> {
        let hello_msg = SyncHelloType::Subscribe {
            delay_milliseconds: delay.as_millis() as u64,
            duration_milliseconds: duration.as_millis() as u64,
            address: self.server_addr,
        };
        let sync_type: runtime::SyncType<Addr> = runtime::SyncType::Hello(hello_msg);
        let data = postcard::to_slice(&sync_type, &mut self.request_buf)
            .context("failed to create subscribe message")?;
        Ok(data.len())
    }

    fn build_hello_unsubscribe(&mut self) -> Result<usize> {
        let hello_msg = SyncHelloType::Unsubscribe {
            address: self.server_addr,
        };
        let sync_type: runtime::SyncType<Addr> = runtime::SyncType::Hello(hello_msg);
        let data = postcard::to_slice(&sync_type, &mut self.request_buf)
            .context("failed to create unsubscribe message")?;
        Ok(data.len())
    }

    fn build_hello_notification(&mut self, head: Address) -> Result<usize> {
        let hello_msg = SyncHelloType::Hello {
            head,
            address: self.server_addr,
        };
        let sync_type: runtime::SyncType<Addr> = runtime::SyncType::Hello(hello_msg);
        let data = postcard::to_slice(&sync_type, &mut self.request_buf)
            .context("failed to create unsubscribe message")?;
        Ok(data.len())
    }
}

/// Shared store of SyncProtocol instances, one per peer.
///
/// This is designed so that a single buffer can be reused across multiple sync operations.
#[derive(Debug, Clone)]
struct ProtocolStore {
    protocols: Arc<DashMap<SyncPeer, Arc<Mutex<SyncProtocol>>>>,
    config: ProtocolConfig,
}

impl ProtocolStore {
    /// Create a new protocol store.
    pub fn new(config: ProtocolConfig) -> Self {
        Self {
            protocols: Arc::default(),
            config,
        }
    }

    /// Get or create the protocol for a peer.
    pub fn get(&self, peer: &SyncPeer) -> Arc<Mutex<SyncProtocol>> {
        let handle = self
            .protocols
            .entry(*peer)
            .or_insert_with(|| Arc::new(Mutex::new(SyncProtocol::new(*peer, self.config.clone()))));
        Arc::clone(&handle)
    }

    /// Remove a peer from the store.
    pub fn remove(&self, peer: &SyncPeer) {
        self.protocols.remove(peer);
    }

    /// Get the number of peers currently stored.
    pub fn len(&self) -> usize {
        self.protocols.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty()
    }
}
