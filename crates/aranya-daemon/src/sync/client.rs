#[cfg(feature = "preview")]
use std::time::Duration;

use anyhow::Context as _;
use aranya_crypto::Rng;
#[cfg(feature = "preview")]
use aranya_runtime::{Address, Storage as _, SyncHelloType, SyncType};
use aranya_runtime::{
    Command as _, PolicyStore, Sink, StorageProvider, SyncRequester, MAX_SYNC_MESSAGE_SIZE,
};
use buggy::BugExt as _;
use derive_where::derive_where;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, trace, warn};

use super::{
    transport::{SyncConnector, SyncStream as _},
    Error, GraphId, Result, SyncPeer, SyncResponse,
};
use crate::{
    aranya::{Client, InvalidGraphs},
    vm_policy::VecSink,
};

/// Handles the actual syncing with other peers.
#[derive_where(Debug; C)]
pub(crate) struct SyncClient<C, PS, SP, EF> {
    /// The Aranya client and peer cache, alongside invalid graph tracking.
    pub(super) client: Client<PS, SP>,
    /// The connector used to create streams with peers.
    connector: C,
    /// Used to send effects to the API to be processed.
    send_effects: mpsc::Sender<(GraphId, Vec<EF>)>,
}

impl<C, PS, SP, EF> SyncClient<C, PS, SP, EF> {
    /// Creates a new [`SyncClient`].
    pub(crate) fn new(
        client: Client<PS, SP>,
        connector: C,
        send_effects: mpsc::Sender<(GraphId, Vec<EF>)>,
    ) -> Self {
        Self {
            client,
            connector,
            send_effects,
        }
    }

    /// Returns a type containing all invalid graphs.
    pub(crate) fn invalid_graphs(&self) -> &InvalidGraphs {
        self.client.invalid_graphs()
    }
}

impl<C, PS, SP, EF> SyncClient<C, PS, SP, EF>
where
    C: SyncConnector,
{
    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    pub(super) async fn send_hello_subscribe(
        &self,
        peer: SyncPeer,
        graph_change_debounce: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Result<()> {
        trace!(?peer, "subscribing to hello notifications from peer");
        // TODO(nikki): update aranya_core with the new name.
        let message = SyncType::Hello(SyncHelloType::Subscribe {
            graph_change_delay: graph_change_debounce,
            duration,
            schedule_delay,
            graph_id: peer.graph_id,
        });

        self.send_hello_request(peer, message).await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    pub(super) async fn send_hello_unsubscribe(&self, peer: SyncPeer) -> Result<()> {
        trace!(?peer, "unsubscribing from hello notifications from peer");
        let message = SyncType::Hello(SyncHelloType::Unsubscribe {
            graph_id: peer.graph_id,
        });

        self.send_hello_request(peer, message).await
    }

    /// Send a hello notification to a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    pub(super) async fn send_hello_notification(
        &mut self,
        peer: SyncPeer,
        head: Address,
    ) -> Result<()> {
        trace!(?peer, "sending hello notifications to peer");

        let message = SyncType::Hello(SyncHelloType::Hello {
            head,
            graph_id: peer.graph_id,
        });
        self.send_hello_request(peer, message).await?;

        Ok(())
    }

    /// Send a hello message to a peer and wait for a response.
    #[cfg(feature = "preview")]
    pub(super) async fn send_hello_request(
        &self,
        peer: SyncPeer,
        sync_type: SyncType,
    ) -> Result<()> {
        // Connect to the peer
        let mut stream = self
            .connector
            .connect(peer)
            .await
            .map_err(Error::transport)?;

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE].into_boxed_slice();

        // Send the message
        let data =
            postcard::to_slice(&sync_type, &mut buf).context("postcard serialization failed")?;
        stream.send(data).await.map_err(Error::transport)?;
        stream.finish().await.map_err(Error::transport)?;

        // Read the response to avoid a race condition with the server
        match stream.receive(&mut buf).await {
            Ok(0) => Err(Error::EmptyResponse),
            Ok(_) => Ok(()),
            Err(e) => Err(Error::transport(e)),
        }
    }
}

impl<C, PS, SP, EF> SyncClient<C, PS, SP, EF>
where
    PS: PolicyStore,
    SP: StorageProvider,
{
    /// Check whether a given command exists in a graph.
    #[cfg(feature = "preview")]
    pub(super) async fn command_exists(&self, graph_id: GraphId, head: Address) -> bool {
        self.client
            .lock_aranya()
            .await
            .command_exists(graph_id, head)
    }

    /// Get the current head address for a graph, if any.
    #[cfg(feature = "preview")]
    pub(super) async fn get_head(&self, graph_id: GraphId) -> Option<Address> {
        self.client
            .lock_aranya()
            .await
            .provider()
            .get_storage(graph_id)
            .map_or(None, |storage| storage.get_head_address().ok())
    }

    /// Update peer cache heads after a hello notification.
    #[cfg(feature = "preview")]
    pub(super) async fn update_heads(&self, peer: SyncPeer, head: Address) -> Result<()> {
        let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
        let cache = caches.entry(peer).or_default();
        aranya.update_heads(peer.graph_id, [head], cache)?;
        Ok(())
    }

    // Process the sync response data and add a new transaction to the Aranya client.
    async fn process_sync_data<S: Sink<PS::Effect>>(
        &self,
        peer: SyncPeer,
        data: &[u8],
        requester: &mut SyncRequester,
        sink: &mut S,
    ) -> Result<usize> {
        // Check if there's even anything to process
        if data.is_empty() {
            debug!(?peer, "sync response contained no data");
            return Ok(0);
        }

        // Check if we actually received any command data.
        let cmds = match requester.receive(data)? {
            Some(cmds) if !cmds.is_empty() => cmds,
            _ => {
                debug!(?peer, "sync response contained no new commands");
                return Ok(0);
            }
        };

        trace!(
            ?peer,
            cmd_count = cmds.len(),
            "processing received commands"
        );

        // Create a new transaction and add all received commands.
        let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
        let mut trx = aranya.transaction(peer.graph_id);
        aranya
            .add_commands(&mut trx, sink, &cmds)
            .context("unable to add received commands")?;
        aranya.commit(&mut trx, sink).context("commit failed")?;

        // Update our peer cache with the new commands.
        aranya
            .update_heads(
                peer.graph_id,
                cmds.iter().filter_map(|cmd| cmd.address().ok()),
                caches.entry(peer).or_default(),
            )
            .context("failed to update cache heads")?;

        debug!(
            ?peer,
            cmd_count = cmds.len(),
            "committed commands from sync"
        );
        Ok(cmds.len())
    }
}

impl<C, PS, SP, EF> SyncClient<C, PS, SP, EF>
where
    C: SyncConnector,
    PS: PolicyStore,
    SP: StorageProvider,
    EF: Send + Sync + 'static + TryFrom<PS::Effect>,
    EF::Error: Send + Sync + 'static + std::error::Error,
{
    /// Handles a sync exchange with a peer.
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    pub(crate) async fn sync(&mut self, peer: SyncPeer) -> Result<usize> {
        debug!(?peer, "starting sync");

        // Connect to the peer.
        let mut stream = self.connector.connect(peer).await.map_err(|error| {
            warn!(?peer, %error, "failed to connect to peer");
            Error::transport(error)
        })?;

        let mut requester = SyncRequester::new(peer.graph_id, Rng);
        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE].into_boxed_slice();

        // Process a poll request, and get back the length/number of commands.
        let (len, _cmds) = {
            let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
            requester
                .poll(&mut buf, aranya.provider(), caches.entry(peer).or_default())
                .context("failed to process poll sync request")
        }?;

        // Send along our request message.
        let buffer = buf.get(..len).assume("valid offset")?;
        trace!(?peer, request_bytes = len, "sending sync request");
        stream.send(buffer).await.map_err(Error::transport)?;
        stream.finish().await.map_err(Error::transport)?;

        // Process the response message.
        let len = stream.receive(&mut buf).await.map_err(Error::transport)?;
        trace!(?peer, response_bytes = len, "received sync response");
        let buffer = buf.get(..len).assume("valid offset")?;
        let resp = postcard::from_bytes(buffer).context("failed to deserialize sync response")?;

        // Destructure the sync response.
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => {
                error!(?peer, %msg, "peer returned sync error");
                return Err(anyhow::anyhow!("sync error: {msg}").into());
            }
        };

        // Process the response data.
        let mut sink = VecSink::new();
        let cmd_count = self
            .process_sync_data(peer, &data, &mut requester, &mut sink)
            .await?;

        // Send all processed effects to the Daemon API.
        let effects = sink.collect().context("could not collect effects")?;
        let effects_count = effects.len();
        if let Err(error) = self.send_effects.send((peer.graph_id, effects)).await {
            debug!(?error, "effect handler closed, discarding effects");
        }

        info!(?peer, cmd_count, effects_count, "sync completed");
        Ok(cmd_count)
    }
}
