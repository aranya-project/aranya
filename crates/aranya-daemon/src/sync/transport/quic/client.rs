#[cfg(feature = "preview")]
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Context as _};
use aranya_crypto::Rng;
use aranya_daemon_api::TeamId;
#[cfg(feature = "preview")]
use aranya_runtime::Address;
use aranya_runtime::{
    Command as _, PolicyStore, Sink, StorageProvider, SyncRequester, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{error::ReportExt as _, rustls::SkipServerVerification};
use buggy::BugExt as _;
use bytes::Bytes;
use futures_util::AsyncReadExt as _;
use s2n_quic::{
    client::Connect,
    connection,
    provider::tls::rustls::{self as rustls_provider, rustls::ClientConfig},
    stream::{BidirectionalStream, ReceiveStream, SendStream},
};
use tokio::sync::mpsc;
use tokio_util::time::DelayQueue;
use tracing::{error, instrument, trace};

use super::{PskStore, SharedConnectionMap, SyncState, ALPN_QUIC_SYNC};
use crate::{
    aranya::Client,
    sync::{
        Addr, Callback, Error, GraphId, Result, SyncManager, SyncPeer, SyncResponse, quic::server::MAX_SYNC_WIRE_MESSAGE_SIZE, transport::quic
    },
};

/// QUIC syncer state used for sending sync requests and processing sync responses
#[derive(Debug)]
pub(crate) struct QuicState {
    /// QUIC client to make sync requests to another peer's sync server and handle sync responses.
    client: s2n_quic::Client,
    /// Address -> Connection map to lookup existing connections before creating a new connection.
    conns: SharedConnectionMap,
    /// PSK store shared between the daemon API server and QUIC syncer client and server.
    /// This store is modified by [`crate::api::DaemonApiServer`].
    store: Arc<PskStore>,
}

impl QuicState {
    /// Get a reference to the PSK store
    #[cfg(feature = "preview")]
    pub(crate) fn store(&self) -> &Arc<PskStore> {
        &self.store
    }

    /// Creates a new instance
    fn new(
        psk_store: Arc<PskStore>,
        conns: SharedConnectionMap,
        client_addr: Addr,
    ) -> Result<Self> {
        // Create client config (INSECURE: skips server cert verification)
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        client_config.preshared_keys = psk_store.clone(); // Pass the Arc<ClientPresharedKeys>

        // Client builder doesn't support adding preshared keys
        #[allow(deprecated)]
        let provider = rustls_provider::Client::new(client_config);

        let client = s2n_quic::Client::builder()
            .with_tls(provider)?
            .with_io((client_addr.host(), client_addr.port()))
            .assume("can set quic client address")?
            .start()
            .map_err(quic::Error::ClientStart)?;

        Ok(Self {
            client,
            conns,
            store: psk_store,
        })
    }
}

impl<PS, SP, EF> SyncState<PS, SP, EF> for QuicState
where
    PS: PolicyStore,
    SP: StorageProvider,
{
    /// Syncs with the peer.
    ///
    /// Aranya client sends a `SyncRequest` to peer then processes the `SyncResponse`.
    #[instrument(skip_all)]
    async fn sync_impl<S: Sink<PS::Effect>>(
        syncer: &mut SyncManager<Self, PS, SP, EF>,
        peer: SyncPeer,
        sink: &mut S,
    ) -> Result<usize> {
        // Sets the active team before starting a QUIC connection
        syncer
            .state
            .store
            .set_team(TeamId::transmute(peer.graph_id));

        let stream = syncer
            .connect(peer)
            .await
            .inspect_err(|e| error!(error = %e.report(), "Could not create connection"))?;
        // TODO: spawn a task for send/recv?
        let (mut recv, mut send) = stream.split();

        let mut sync_requester = SyncRequester::new(peer.graph_id, Rng);

        // send sync request.
        syncer
            .send_sync_request(&mut send, &mut sync_requester, peer)
            .await
            .map_err(|e| Error::SendSyncRequest(e.into()))?;

        // receive sync response.
        let cmd_count = syncer
            .receive_sync_response(&mut recv, &mut sync_requester, sink, peer)
            .await
            .map_err(|e| Error::ReceiveSyncResponse(e.into()))?;

        Ok(cmd_count)
    }

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all)]
    async fn sync_hello_subscribe_impl(
        syncer: &mut SyncManager<Self, PS, SP, EF>,
        peer: SyncPeer,
        graph_change_debounce: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Result<()> {
        syncer
            .state
            .store()
            .set_team(TeamId::transmute(peer.graph_id));
        syncer
            .send_sync_hello_subscribe_request(
                peer,
                graph_change_debounce,
                duration,
                schedule_delay,
            )
            .await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all)]
    async fn sync_hello_unsubscribe_impl(
        syncer: &mut SyncManager<Self, PS, SP, EF>,
        peer: SyncPeer,
    ) -> Result<()> {
        syncer
            .state
            .store()
            .set_team(TeamId::transmute(peer.graph_id));
        syncer.send_hello_unsubscribe_request(peer).await
    }

    /// Broadcast hello notifications to all subscribers of a graph.
    #[cfg(feature = "preview")]
    #[instrument(skip_all)]
    async fn broadcast_hello_notifications_impl(
        syncer: &mut SyncManager<Self, PS, SP, EF>,
        graph_id: GraphId,
        head: Address,
    ) -> Result<()> {
        syncer.broadcast_hello_notifications(graph_id, head).await
    }
}

impl<PS, SP, EF> SyncManager<QuicState, PS, SP, EF>
where
    PS: PolicyStore,
    SP: StorageProvider,
{
    /// Creates a new [`SyncManager`].
    pub(crate) fn new(
        client: Client<PS, SP>,
        send_effects: mpsc::Sender<(GraphId, Vec<EF>)>,
        psk_store: Arc<PskStore>,
        (server_addr, client_addr): (Addr, Addr),
        recv: mpsc::Receiver<Callback>,
        conns: SharedConnectionMap,
    ) -> Result<Self> {
        let state = QuicState::new(psk_store, conns.clone(), client_addr)?;

        let return_port = Bytes::copy_from_slice(&server_addr.port().to_be_bytes());

        Ok(Self {
            client,
            peers: HashMap::new(),
            recv,
            queue: DelayQueue::new(),
            send_effects,
            state,
            return_port,
            #[cfg(feature = "preview")]
            hello_tasks: tokio::task::JoinSet::new(),
        })
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
    /// * `Ok(BidirectionalStream)` if the connection and stream were established successfully
    /// * `Err(SyncError)` if there was an error connecting or opening the stream
    #[instrument(skip_all)]
    pub(crate) async fn connect(&mut self, peer: SyncPeer) -> Result<BidirectionalStream> {
        trace!("client connecting to QUIC sync server");
        // Check if there is an existing connection with the peer.
        // If not, create a new connection.

        let addr = tokio::net::lookup_host(peer.addr.to_socket_addrs())
            .await
            .context("DNS lookup on for peer address")?
            .next()
            .context("could not resolve peer address")?;

        let client = &self.state.client;

        let mut handle = self
            .state
            .conns
            .get_or_try_insert_with(peer, async || {
                let mut conn = client
                    .connect(Connect::new(addr).with_server_name(addr.ip().to_string()))
                    .await?;
                conn.keep_alive(true)?;
                conn.open_send_stream()
                    .await?
                    .send(self.return_port.clone())
                    .await?;
                Ok(conn)
            })
            .await?;

        trace!("client connected to QUIC sync server");

        let open_stream_res = handle
            .open_bidirectional_stream()
            .await
            .inspect_err(|e| error!(error = %e.report(), "unable to open bidi stream"));
        let stream = match open_stream_res {
            Ok(stream) => stream,
            // Retry for these errors?
            Err(e @ connection::Error::StatelessReset { .. })
            | Err(e @ connection::Error::StreamIdExhausted { .. })
            | Err(e @ connection::Error::MaxHandshakeDurationExceeded { .. }) => {
                return Err(Error::QuicSync(e.into()));
            }
            // Other errors means the stream has closed
            Err(e) => {
                self.state.conns.remove(peer, handle).await;
                return Err(Error::QuicSync(e.into()));
            }
        };

        trace!("client opened bidi stream with QUIC sync server");
        Ok(stream)
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
    async fn send_sync_request(
        &self,
        send: &mut SendStream,
        syncer: &mut SyncRequester,
        peer: SyncPeer,
    ) -> Result<()> {
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

        send.send(Bytes::from(send_buf))
            .await
            .map_err(quic::Error::from)?;
        send.close().await.map_err(quic::Error::from)?;
        trace!("sent sync request");

        Ok(())
    }

    #[instrument(skip_all)]
    /// Receives and processes a sync response from the server.
    ///
    /// Returns the number of commands that were received and successfully processed.
    async fn receive_sync_response<S>(
        &self,
        recv: &mut ReceiveStream,
        syncer: &mut SyncRequester,
        sink: &mut S,
        peer: SyncPeer,
    ) -> Result<usize>
    where
        S: Sink<PS::Effect>,
    {
        trace!("client receiving sync response from QUIC sync server");

        let mut recv_buf = Vec::new();
        let cap_plus_one = MAX_SYNC_WIRE_MESSAGE_SIZE + 1;

        recv.take(cap_plus_one as u64)
            .read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync response")?;

        debug_assert!(
            recv_buf.len() <= cap_plus_one,
            "bounded read invariant violated: len={} cap_plus_one={}",
            recv_buf.len(),
            cap_plus_one
        );

        if recv_buf.len() > MAX_SYNC_WIRE_MESSAGE_SIZE {
            return Err(anyhow!(
                "sync response too large: {} > {} bytes",
                recv_buf.len(),
                MAX_SYNC_WIRE_MESSAGE_SIZE
            )
            .into());
        }
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
