//! QUIC client for syncing Aranya graph commands with peers.

use std::{collections::HashMap, time::Duration};

use anyhow::Context as _;
use aranya_crypto::Rng;
#[cfg(feature = "preview")]
use aranya_runtime::Address;
use aranya_runtime::{
    Command as _, Engine, Sink, StorageProvider, SyncRequester, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::error::ReportExt as _;
use quinn::{Endpoint, RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::mpsc;
use tokio_util::time::DelayQueue;
use tracing::{debug, error, instrument, trace};

use super::{ConnectionKey, Error, SharedConnectionMap};
use crate::{
    aranya::Client,
    sync::{
        transport::SyncState, Addr, Callback, GraphId, Result, SyncManager, SyncPeer, SyncResponse,
    },
};

/// QUIC syncer state used for sending sync requests and processing sync responses
#[derive(Debug)]
pub(crate) struct QuicState {
    /// QUIC endpoint for both client and server operations.
    endpoint: Endpoint,
    /// Client TLS configuration for outbound connections.
    client_config: quinn::ClientConfig,
    /// Address -> Connection map to lookup existing connections before creating a new connection.
    conns: SharedConnectionMap,
}

impl QuicState {
    /// Creates a new instance using a shared endpoint.
    ///
    /// The endpoint is created by [`Server::new()`] and shared with the SyncManager.
    /// Using a single endpoint ensures that outbound connections use the server's
    /// bound address as the source, enabling bidirectional connection reuse.
    pub(super) fn new(
        endpoint: Endpoint,
        client_config: quinn::ClientConfig,
        conns: SharedConnectionMap,
    ) -> Self {
        Self {
            endpoint,
            client_config,
            conns,
        }
    }
}

impl<EN, SP, EF> SyncState<EN, SP, EF> for QuicState
where
    EN: Engine,
    SP: StorageProvider,
{
    /// Syncs with the peer.
    ///
    /// Aranya client sends a `SyncRequest` to peer then processes the `SyncResponse`.
    #[instrument(skip_all)]
    async fn sync_impl<S: Sink<EN::Effect>>(
        syncer: &mut SyncManager<Self, EN, SP, EF>,
        peer: SyncPeer,
        sink: &mut S,
    ) -> Result<usize> {
        let (mut send, mut recv) = syncer
            .connect(peer)
            .await
            .inspect_err(|e| error!(error = %e.report(), "Could not create connection"))?;

        let mut sync_requester = SyncRequester::new(peer.graph_id, &mut Rng, syncer.server_addr);

        // send sync request.
        syncer
            .send_sync_request(&mut send, &mut sync_requester, peer)
            .await
            .map_err(|e| crate::sync::Error::SendSyncRequest(e.into()))?;

        // receive sync response.
        let cmd_count = syncer
            .receive_sync_response(&mut recv, &mut sync_requester, sink, peer)
            .await
            .map_err(|e| crate::sync::Error::ReceiveSyncResponse(e.into()))?;

        Ok(cmd_count)
    }

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all)]
    async fn sync_hello_subscribe_impl(
        syncer: &mut SyncManager<Self, EN, SP, EF>,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Result<()> {
        syncer
            .send_sync_hello_subscribe_request(
                peer,
                graph_change_delay,
                duration,
                schedule_delay,
                syncer.server_addr,
            )
            .await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all)]
    async fn sync_hello_unsubscribe_impl(
        syncer: &mut SyncManager<Self, EN, SP, EF>,
        peer: SyncPeer,
    ) -> Result<()> {
        syncer
            .send_hello_unsubscribe_request(peer, syncer.server_addr)
            .await
    }

    /// Broadcast hello notifications to all subscribers of a graph.
    #[cfg(feature = "preview")]
    #[instrument(skip_all)]
    async fn broadcast_hello_notifications_impl(
        syncer: &mut SyncManager<Self, EN, SP, EF>,
        graph_id: GraphId,
        head: Address,
    ) -> Result<()> {
        syncer.broadcast_hello_notifications(graph_id, head).await
    }
}

impl<EN, SP, EF> SyncManager<QuicState, EN, SP, EF>
where
    EN: Engine,
    SP: StorageProvider,
{
    /// Creates a new [`SyncManager`].
    ///
    /// The `endpoint` and `client_config` should come from [`Server::new()`] to ensure
    /// that outbound connections use the same endpoint as the server, enabling
    /// bidirectional connection reuse.
    pub(crate) fn new(
        client: Client<EN, SP>,
        send_effects: mpsc::Sender<(GraphId, Vec<EF>)>,
        server_addr: Addr,
        recv: mpsc::Receiver<Callback>,
        conns: SharedConnectionMap,
        endpoint: Endpoint,
        client_config: quinn::ClientConfig,
    ) -> Self {
        let state = QuicState::new(endpoint, client_config, conns);

        Self {
            client,
            peers: HashMap::new(),
            recv,
            queue: DelayQueue::new(),
            send_effects,
            state,
            server_addr,
            #[cfg(feature = "preview")]
            hello_tasks: tokio::task::JoinSet::new(),
        }
    }

    /// Establishes a QUIC connection to a peer and opens a bidirectional stream.
    ///
    /// This method first checks if there's an existing connection to the peer.
    /// If not, it creates a new QUIC connection. Then it opens a bidirectional
    /// stream for sending sync requests and receiving responses.
    ///
    /// # Arguments
    /// * `peer` - The unique identifier of the peer to connect to
    ///
    /// # Returns
    /// * `Ok((SendStream, RecvStream))` if the connection and stream were established successfully
    /// * `Err(SyncError)` if there was an error connecting or opening the stream
    #[instrument(skip_all)]
    pub(crate) async fn connect(&mut self, peer: SyncPeer) -> Result<(SendStream, RecvStream)> {
        trace!("client connecting to QUIC sync server");

        let endpoint = &self.state.endpoint;

        // Get the local address to determine IP version (IPv4 vs IPv6).
        // We need to filter DNS results to match the endpoint's IP version
        // because QUIC can't connect to IPv6 from an IPv4-bound endpoint.
        let local_addr = endpoint
            .local_addr()
            .map_err(|e| Error::EndpointError(format!("unable to get local address: {e}")))?;
        let local_is_ipv4 = local_addr.is_ipv4();

        let addr = tokio::net::lookup_host(peer.addr.to_socket_addrs())
            .await
            .context("DNS lookup for peer address")?
            .find(|addr| addr.is_ipv4() == local_is_ipv4)
            .context("could not resolve peer address to matching IP version")?;

        let key = ConnectionKey::new(addr);
        let client_config = self.state.client_config.clone();
        let peer_host = peer.addr.host().to_string();

        let conn = self
            .state
            .conns
            .get_or_try_insert_with(key, async || {
                let connecting = endpoint
                    .connect_with(client_config, addr, &peer_host)
                    .map_err(Error::from)?;

                // Add timeout to connection attempt to avoid hanging on failed TLS handshakes
                let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
                    .await
                    .map_err(|_| Error::QuicConnectionTimeout)?
                    .map_err(Error::from)?;

                debug!(%addr, "established new QUIC connection to peer");
                Ok::<_, Error>(conn)
            })
            .await?;

        trace!("client connected to QUIC sync server");

        let (send, recv) = conn
            .open_bi()
            .await
            .inspect_err(|e| error!(error = %e, "unable to open bidi stream"))
            .map_err(|e| {
                // If the stream fails to open, the connection may be closed
                if conn.close_reason().is_some() {
                    // Remove the closed connection
                    let mut conns = self.state.conns.clone();
                    let conn_clone = conn.clone();
                    tokio::spawn(async move {
                        conns.remove(key, conn_clone).await;
                    });
                }
                crate::sync::Error::QuicSync(Error::QuicConnectionError(e))
            })?;

        trace!("client opened bidi stream with QUIC sync server");
        Ok((send, recv))
    }

    /// Sends a sync request to a peer over an established QUIC stream.
    ///
    /// This method uses the SyncRequester to generate the sync request data,
    /// serializes it, and sends it over the provided QUIC send stream.
    ///
    /// # Arguments
    /// * `send` - The QUIC send stream to use for sending the request
    /// * `syncer` - The SyncRequester instance that generates the sync request
    /// * `peer` - The unique identifier of the peer to send the message to
    ///
    /// # Returns
    /// * `Ok(())` if the sync request was sent successfully
    /// * `Err(SyncError)` if there was an error generating or sending the request
    #[instrument(skip_all)]
    async fn send_sync_request<A>(
        &self,
        send: &mut SendStream,
        syncer: &mut SyncRequester<A>,
        peer: SyncPeer,
    ) -> Result<()>
    where
        A: Serialize + DeserializeOwned + Clone,
    {
        trace!("client sending sync request to QUIC sync server");
        let mut send_buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        let len = {
            // Lock both aranya and caches in the correct order.
            let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
            let cache = caches.entry(peer).or_default();
            let (len, _) = syncer
                .poll(&mut send_buf, aranya.provider(), cache)
                .context("sync poll failed")?;
            trace!(?len, "sync poll finished");
            len
        };
        send_buf.truncate(len);

        send.write_all(&send_buf)
            .await
            .map_err(Error::QuicWriteError)?;
        send.finish().map_err(|_| {
            Error::QuicWriteError(quinn::WriteError::ConnectionLost(
                quinn::ConnectionError::LocallyClosed,
            ))
        })?;
        trace!("sent sync request");

        Ok(())
    }

    /// Receives and processes a sync response from the server.
    ///
    /// Returns the number of commands that were received and successfully processed.
    #[instrument(skip_all)]
    async fn receive_sync_response<S, A>(
        &self,
        recv: &mut RecvStream,
        syncer: &mut SyncRequester<A>,
        sink: &mut S,
        peer: SyncPeer,
    ) -> Result<usize>
    where
        S: Sink<EN::Effect>,
        A: Serialize + DeserializeOwned + Clone,
    {
        trace!("client receiving sync response from QUIC sync server");

        let recv_buf = recv
            .read_to_end(MAX_SYNC_MESSAGE_SIZE)
            .await
            .map_err(Error::QuicReadError)?;
        trace!(n = recv_buf.len(), "received sync response");

        // process the sync response.
        let resp = postcard::from_bytes(&recv_buf)
            .context("postcard unable to deserialize sync response")?;
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => return Err(anyhow::anyhow!("sync error: {msg}").into()),
        };
        if data.is_empty() {
            trace!("nothing to sync");
            return Ok(0);
        }
        if let Some(cmds) = syncer.receive(&data)? {
            trace!(num = cmds.len(), "received commands");
            if !cmds.is_empty() {
                // Lock both aranya and caches in the correct order.
                let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
                let mut trx = aranya.transaction(peer.graph_id);
                aranya
                    .add_commands(&mut trx, sink, &cmds)
                    .context("unable to add received commands")?;
                aranya.commit(&mut trx, sink).context("commit failed")?;
                trace!("committed");
                let cache = caches.entry(peer).or_default();
                aranya
                    .update_heads(
                        peer.graph_id,
                        cmds.iter().filter_map(|cmd| cmd.address().ok()),
                        cache,
                    )
                    .context("failed to update cache heads")?;
                return Ok(cmds.len());
            }
        }

        Ok(0)
    }
}
