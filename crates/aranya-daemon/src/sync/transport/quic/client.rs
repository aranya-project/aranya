use std::{collections::HashMap, convert::Infallible, net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::Context;
use aranya_crypto::Rng;
use aranya_runtime::{
    Address, Command, Engine, GraphId, Sink, SyncRequester, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{error::ReportExt as _, rustls::SkipServerVerification, Addr};
use buggy::BugExt as _;
use bytes::Bytes;
use s2n_quic::{
    client::Connect,
    connection::Error as ConnErr,
    provider::{
        tls::{rustls as rustls_provider, rustls::rustls::ClientConfig},
        StartError,
    },
    stream::{BidirectionalStream, ReceiveStream, SendStream},
    Client as QuicClient,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, Mutex},
};
use tokio_util::time::DelayQueue;
use tracing::{debug, error, instrument};

use crate::{
    aranya::ClientWithCaches,
    sync::{
        manager::{EffectSender, Request, SyncHandle, SyncManager},
        services::hello::HelloSubscriptions,
        transport::{
            quic::{
                connections::{ConnectionKey, ConnectionUpdate, SharedConnectionMap},
                psk::PskStore,
                ALPN_QUIC_SYNC,
            },
            Transport,
        },
        types::{SyncPeer, SyncResponse},
        Result as SyncResult, SyncError,
    },
    InvalidGraphs,
};

/// Errors specific to the QUIC syncer
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// QUIC Connection error
    #[error(transparent)]
    QuicConnectionError(#[from] s2n_quic::connection::Error),
    /// QUIC Stream error
    #[error(transparent)]
    QuicStreamError(#[from] s2n_quic::stream::Error),
    /// Invalid PSK used for syncing
    #[error("invalid PSK used when attempting to sync")]
    InvalidPSK,
    /// QUIC client endpoint start error
    #[error("could not start QUIC client")]
    ClientStart(#[source] StartError),
    /// QUIC server endpoint start error
    #[error("could not start QUIC server")]
    ServerStart(#[source] StartError),
}

impl From<Infallible> for Error {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

/// QUIC syncer state used for sending sync requests and processing sync responses
#[derive(Debug)]
pub struct State {
    /// QUIC client to make sync requests to another peer's sync server and handle sync responses.
    client: QuicClient,
    /// Address -> Connection map to lookup existing connections before creating a new connection.
    conns: SharedConnectionMap,
    /// PSK store shared between the daemon API server and QUIC syncer client and server.
    /// This store is modified by [`crate::api::DaemonApiServer`].
    store: Arc<PskStore>,
    /// Shared reference to hello subscriptions for broadcasting notifications
    hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
}

impl Transport for State {
    /// Syncs with the peer.
    ///
    /// Aranya client sends a `SyncRequest` to peer then processes the `SyncResponse`.
    async fn execute_sync(
        &self,
        peer: &SyncPeer,
        request: &[u8],
        response: &mut [u8],
    ) -> SyncResult<usize> {
        Ok(0)
        /*
        // Sets the active team before starting a QUIC connection
        syncer.state.store().set_team(id.into_id().into());

        let stream = syncer
            .connect(peer, id)
            .await
            .inspect_err(|e| error!(error = %e.report(), "Could not create connection"))?;
        // TODO: spawn a task for send/recv?
        let (mut recv, mut send) = stream.split();

        let mut sync_requester = SyncRequester::new(id, &mut Rng, syncer.server_addr);

        // send sync request.
        syncer
            .send_sync_request(&mut send, &mut sync_requester, id, peer)
            .await
            .map_err(|e| SyncError::SendSyncRequest(Box::new(e)))?;

        // receive sync response.
        let cmd_count = syncer
            .receive_sync_response(&mut recv, &mut sync_requester, &id, sink, peer)
            .await
            .map_err(|e| SyncError::ReceiveSyncResponse(Box::new(e)))?;

        Ok(cmd_count)
        */
    }

    /// Subscribe to hello notifications from a sync peer.
    #[instrument(skip_all)]
    async fn sync_hello_subscribe_impl(
        syncer: &mut SyncManager<Self>,
        id: GraphId,
        peer: &Addr,
        delay: Duration,
        duration: Duration,
    ) -> SyncResult<()> {
        syncer.state.store().set_team(id.into_id().into());
        syncer
            .send_sync_hello_subscribe_request(peer, id, delay, duration, syncer.server_addr)
            .await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[instrument(skip_all)]
    async fn sync_hello_unsubscribe_impl(
        syncer: &mut SyncManager<Self>,
        id: GraphId,
        peer: &Addr,
    ) -> SyncResult<()> {
        syncer.state.store().set_team(id.into_id().into());
        syncer
            .send_hello_unsubscribe_request(peer, id, syncer.server_addr)
            .await
    }

    /// Broadcast hello notifications to all subscribers of a graph.
    #[instrument(skip_all)]
    async fn broadcast_hello_notifications(
        syncer: &mut SyncManager<Self>,
        graph_id: GraphId,
        head: Address,
    ) -> SyncResult<()> {
        syncer.broadcast_hello_notifications(graph_id, head).await
    }
}

impl State {
    /// Get a reference to the PSK store
    pub fn store(&self) -> &Arc<PskStore> {
        &self.store
    }

    /// Get a reference to the hello subscriptions
    pub fn hello_subscriptions(&self) -> &Arc<Mutex<HelloSubscriptions>> {
        &self.hello_subscriptions
    }

    /// Creates a new instance
    fn new(
        psk_store: Arc<PskStore>,
        conns: SharedConnectionMap,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
    ) -> SyncResult<Self> {
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

        let client = QuicClient::builder()
            .with_tls(provider)?
            .with_io((Ipv4Addr::UNSPECIFIED, 0))
            .assume("can set quic client address")?
            .start()
            .map_err(Error::ClientStart)?;

        Ok(Self {
            client,
            conns,
            store: psk_store,
            hello_subscriptions,
        })
    }
}

impl SyncManager<State> {
    /// Creates a new [`Syncer`].
    pub(crate) fn new(
        client_with_caches: ClientWithCaches<crate::EN, crate::SP>,
        send_effects: EffectSender,
        invalid: InvalidGraphs,
        psk_store: Arc<PskStore>,
        server_addr: Addr,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
    ) -> SyncResult<(
        Self,
        SyncHandle,
        SharedConnectionMap,
        mpsc::Receiver<ConnectionUpdate>,
    )> {
        let (send, recv) = mpsc::channel::<Request>(128);
        let peers = SyncHandle::new(send);

        let (conns, conn_rx) = SharedConnectionMap::new();
        let state = State::new(psk_store, conns.clone(), hello_subscriptions)?;

        Ok((
            Self {
                client_with_caches,
                peers: HashMap::new(),
                recv,
                queue: DelayQueue::new(),
                send_effects,
                invalid,
                state,
                server_addr,
            },
            peers,
            conns,
            conn_rx,
        ))
    }

    /// Establishes a QUIC connection to a peer and opens a bidirectional stream.
    ///
    /// This method first checks if there's an existing connection to the peer.
    /// If not, it creates a new QUIC connection. Then it opens a bidirectional
    /// stream for sending sync requests and receiving responses.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to connect to
    /// * `id` - The graph ID for the team/graph to sync with
    ///
    /// # Returns
    /// * `Ok(BidirectionalStream)` if the connection and stream were established successfully
    /// * `Err(SyncError)` if there was an error connecting or opening the stream
    #[instrument(skip_all)]
    pub(crate) async fn connect(
        &mut self,
        peer: &Addr,
        id: GraphId,
    ) -> SyncResult<BidirectionalStream> {
        debug!("client connecting to QUIC sync server");
        // Check if there is an existing connection with the peer.
        // If not, create a new connection.

        let addr = tokio::net::lookup_host(peer.to_socket_addrs())
            .await
            .context("DNS lookup on for peer address")?
            .next()
            .context("could not resolve peer address")?;

        let key = ConnectionKey { addr, id };
        let client = &self.state.client;

        let mut handle = self
            .state
            .conns
            .get_or_try_insert_with(key, async || {
                let mut conn = client
                    .connect(Connect::new(addr).with_server_name(addr.ip().to_string()))
                    .await?;
                conn.keep_alive(true)?;
                Ok(conn)
            })
            .await?;

        debug!("client connected to QUIC sync server");

        let open_stream_res = handle
            .open_bidirectional_stream()
            .await
            .inspect_err(|e| error!(error = %e.report(), "unable to open bidi stream"));
        let stream = match open_stream_res {
            Ok(stream) => stream,
            // Retry for these errors?
            Err(e @ ConnErr::StatelessReset { .. })
            | Err(e @ ConnErr::StreamIdExhausted { .. })
            | Err(e @ ConnErr::MaxHandshakeDurationExceeded { .. }) => {
                return Err(SyncError::QuicSync(e.into()));
            }
            // Other errors means the stream has closed
            Err(e) => {
                self.state.conns.remove(key, handle).await;
                return Err(SyncError::QuicSync(e.into()));
            }
        };

        debug!("client opened bidi stream with QUIC sync server");
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
    /// * `id` - The graph ID for the team/graph to sync
    /// * `peer` - The network address of the peer
    ///
    /// # Returns
    /// * `Ok(())` if the sync request was sent successfully
    /// * `Err(SyncError)` if there was an error generating or sending the request
    #[instrument(skip_all)]
    pub(crate) async fn send_sync_request<A>(
        &self,
        send: &mut SendStream,
        syncer: &mut SyncRequester<A>,
        id: GraphId,
        peer: &Addr,
    ) -> SyncResult<()>
    where
        A: Serialize + DeserializeOwned + Clone,
    {
        debug!("client sending sync request to QUIC sync server");
        let mut send_buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        let len = {
            // Lock both aranya and caches in the correct order.
            let (mut aranya, mut caches) = self.client_with_caches.lock_aranya_and_caches().await;
            let key = SyncPeer::new(*peer, id);
            let cache = caches.entry(key).or_default();
            let (len, _) = syncer
                .poll(&mut send_buf, aranya.provider(), cache)
                .context("sync poll failed")?;
            debug!(?len, "sync poll finished");
            len
        };
        send_buf.truncate(len);

        send.send(Bytes::from(send_buf))
            .await
            .map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;
        debug!("sent sync request");

        Ok(())
    }

    #[instrument(skip_all)]
    /// Receives and processes a sync response from the server.
    ///
    /// Returns the number of commands that were received and successfully processed.
    pub async fn receive_sync_response<S, A>(
        &self,
        recv: &mut ReceiveStream,
        syncer: &mut SyncRequester<A>,
        id: &GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> SyncResult<usize>
    where
        S: Sink<<crate::EN as Engine>::Effect>,
        A: Serialize + DeserializeOwned + Clone,
    {
        debug!("client receiving sync response from QUIC sync server");

        let mut recv_buf = Vec::new();
        recv.read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync response")?;
        debug!(n = recv_buf.len(), "received sync response");

        // Check for empty response (which indicates a hello message response)
        if recv_buf.is_empty() {
            debug!("received empty response, likely from hello message - ignoring");
            return Ok(0);
        }

        // process the sync response.
        let resp = postcard::from_bytes(&recv_buf)
            .context("postcard unable to deserialize sync response")?;
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => return Err(anyhow::anyhow!("sync error: {msg}").into()),
        };
        if data.is_empty() {
            debug!("nothing to sync");
            return Ok(0);
        }
        if let Some(cmds) = syncer.receive(&data)? {
            debug!(num = cmds.len(), "received commands");
            if !cmds.is_empty() {
                // Lock both aranya and caches in the correct order.
                let (mut aranya, mut caches) =
                    self.client_with_caches.lock_aranya_and_caches().await;
                let mut trx = aranya.transaction(*id);
                aranya
                    .add_commands(&mut trx, sink, &cmds)
                    .context("unable to add received commands")?;
                aranya.commit(&mut trx, sink).context("commit failed")?;
                debug!("committed");
                let key = SyncPeer::new(*peer, *id);
                let cache = caches.entry(key).or_default();
                aranya
                    .update_heads(*id, cmds.iter().filter_map(|cmd| cmd.address().ok()), cache)
                    .context("failed to update cache heads")?;
                return Ok(cmds.len());
            }
        }

        Ok(0)
    }
}
