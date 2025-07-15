//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with a rustls PSK.
//! A different PSK will be used for each Aranya team.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use core::net::SocketAddr;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    future::Future,
    net::Ipv4Addr,
    sync::Arc,
};

use anyhow::Context;
use aranya_crypto::Rng;
use aranya_daemon_api::TeamId;
use aranya_runtime::{
    Engine, GraphId, PeerCache, Sink, StorageError, StorageProvider, SyncRequestMessage,
    SyncRequester, SyncResponder, SyncType, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{
    rustls::{NoCertResolver, SkipServerVerification},
    task::scope,
    Addr,
};
use buggy::{bug, BugExt as _};
use bytes::Bytes;
use derive_where::derive_where;
#[allow(deprecated)]
use s2n_quic::provider::tls::rustls::rustls::{
    server::PresharedKeySelection, ClientConfig, ServerConfig,
};
use s2n_quic::{
    client::Connect,
    connection::Error as ConnErr,
    provider::{
        congestion_controller::Bbr,
        tls::rustls::{self as rustls_provider, rustls::server::SelectsPresharedKeys},
    },
    stream::{BidirectionalStream, ReceiveStream, SendStream},
    Client as QuicClient, Connection, Server as QuicServer,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{io::AsyncReadExt, sync::mpsc};
use tracing::{debug, error, info, instrument, warn};

use super::SyncResponse;
use crate::{
    aranya::Client as AranyaClient,
    sync::{
        task::{SyncState, Syncer},
        Result as SyncResult, SyncError,
    },
};

mod psk;

pub(crate) use psk::PskSeed;
pub use psk::PskStore;

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic-sync-unstable";

/// Errors specific to the QUIC syncer
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// QUIC Connection error
    #[error("QUIC connection error: {0}")]
    QuicConnectionError(#[from] s2n_quic::connection::Error),
    /// QUIC Stream error
    #[error("QUIC stream error: {0}")]
    QuicStreamError(#[from] s2n_quic::stream::Error),
    /// QUIC client config error
    #[error("QUIC client config error: {0}")]
    ClientConfig(anyhow::Error),
    /// Invalid PSK used for syncing
    #[error("Invalid PSK used when attempting to sync")]
    InvalidPSK,
    /// QUIC server config error
    #[error("QUIC server config error: {0}")]
    ServerConfig(anyhow::Error),
    /// An unexpected error occured
    #[error("An unexpected error occured: {0}")]
    Bug(buggy::Bug),
}

/// QUIC syncer state used for sending sync requests and processing sync responses
#[derive(Debug)]
pub struct State {
    /// QUIC client to make sync requests to another peer's sync server and handle sync responses.
    client: QuicClient,
    /// Address -> Connection map to lookup existing connections before creating a new connection.
    conns: BTreeMap<Addr, Connection>,
    /// PSK store shared between the daemon API server and QUIC syncer client and server.
    /// This store is modified by [`crate::api::DaemonApiServer`].
    store: Arc<PskStore>,
}

impl SyncState for State {
    #[allow(clippy::manual_async_fn)]
    #[instrument(skip(syncer, sink))]
    /// Syncs with the peer.
    /// Aranya client sends a `SyncRequest` to peer then processes the `SyncResponse`.
    fn sync_impl<S>(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> impl Future<Output = SyncResult<()>> + Send
    where
        S: Sink<<crate::EN as Engine>::Effect> + Send,
    {
        async move {
            // Sets the active team before starting a QUIC connection
            syncer.state.store.set_team(id.into_id().into());

            let stream = syncer
                .connect(peer)
                .await
                .inspect_err(|e| error!("Could not create connection: {e}"))?;
            // TODO: spawn a task for send/recv?
            let (mut recv, mut send) = stream.split();

            // TODO: Real server address.
            let server_addr = ();
            let mut sync_requester = SyncRequester::new(id, &mut Rng, server_addr);

            // send sync request.
            syncer
                .send_sync_request(&mut send, &mut sync_requester, peer)
                .await
                .map_err(|e| SyncError::SendSyncRequest(Box::new(e)))?;

            // receive sync response.
            syncer
                .receive_sync_response(&mut recv, &mut sync_requester, &id, sink, peer)
                .await
                .map_err(|e| SyncError::ReceiveSyncResponse(Box::new(e)))?;

            Ok(())
        }
    }
}

impl State {
    /// Creates a new instance
    pub fn new(psk_store: Arc<PskStore>) -> SyncResult<Self>
where {
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
            .with_tls(provider)
            .context("can't set quic client config")
            .map_err(Error::ClientConfig)?
            .with_io((Ipv4Addr::UNSPECIFIED, 0))
            .assume("can set quic client addr")
            .map_err(Error::Bug)?
            .start()
            .context("can't start quic client")
            .map_err(Error::ClientConfig)?;

        Ok(Self {
            client,
            conns: BTreeMap::new(),
            store: psk_store,
        })
    }
}

impl Syncer<State> {
    #[instrument(skip(self))]
    async fn connect(&mut self, peer: &Addr) -> SyncResult<BidirectionalStream> {
        info!(?peer, "client connecting to QUIC sync server");
        // Check if there is an existing connection with the peer.
        // If not, create a new connection.
        let conns = &mut self.state.conns;
        let client = &self.state.client;

        let conn = match conns.entry(*peer) {
            Entry::Occupied(entry) => {
                info!("Client is able to re-use existing QUIC connection");
                entry.into_mut()
            }
            Entry::Vacant(entry) => {
                info!(?peer, "existing QUIC connection not found");

                let addr = tokio::net::lookup_host(peer.to_socket_addrs())
                    .await
                    .context("DNS lookup on for peer address")?
                    .next()
                    .assume("invalid peer address")?;
                // Note: cert is not used but server name must be set to connect.
                debug!(?peer, "attempting to create new quic connection");

                let mut conn = client
                    .connect(Connect::new(addr).with_server_name("127.0.0.1"))
                    .await
                    .map_err(Error::from)?;

                conn.keep_alive(true).map_err(Error::from)?;
                debug!(?peer, "created new quic connection");
                entry.insert(conn)
            }
        };

        info!("client connected to QUIC sync server");

        let open_stream_res = conn
            .handle()
            .open_bidirectional_stream()
            .await
            .inspect_err(|e| error!(?peer, "unable to open bidi stream: {}", e));
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
                conns.remove(peer);
                return Err(SyncError::QuicSync(e.into()));
            }
        };

        info!(?peer, "client opened bidi stream with QUIC sync server");
        Ok(stream)
    }

    #[instrument(skip(self, syncer))]
    async fn send_sync_request<A>(
        &self,
        send: &mut SendStream,
        syncer: &mut SyncRequester<'_, A>,
        peer: &Addr,
    ) -> SyncResult<()>
    where
        A: Serialize + DeserializeOwned + Clone,
    {
        info!("client sending sync request to QUIC sync server");
        let mut send_buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        let (len, _) = {
            let mut client = self.client.lock().await;
            // TODO: save PeerCache somewhere.
            syncer
                .poll(&mut send_buf, client.provider(), &mut PeerCache::new())
                .context("sync poll failed")?
        };
        debug!(?len, "sync poll finished");
        send_buf.truncate(len);

        send.send(Bytes::from(send_buf))
            .await
            .map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;
        debug!(?peer, "sent sync request");

        Ok(())
    }

    #[instrument(skip(self, syncer, sink))]
    async fn receive_sync_response<S, A>(
        &self,
        recv: &mut ReceiveStream,
        syncer: &mut SyncRequester<'_, A>,
        id: &GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> SyncResult<()>
    where
        S: Sink<<crate::EN as Engine>::Effect>,
        A: Serialize + DeserializeOwned + Clone,
    {
        info!("client receiving sync response from QUIC sync server");

        let mut recv_buf = Vec::new();
        recv.read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync response")?;
        debug!(?peer, n = recv_buf.len(), "received sync response");

        // process the sync response.
        let resp = postcard::from_bytes(&recv_buf)
            .context("postcard unable to deserialize sync response")?;
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => return Err(anyhow::anyhow!("sync error: {msg}").into()),
        };
        if data.is_empty() {
            debug!("nothing to sync");
            return Ok(());
        }
        if let Some(cmds) = syncer.receive(&data)? {
            debug!(num = cmds.len(), "received commands");
            if !cmds.is_empty() {
                let mut client = self.client.lock().await;
                let mut trx = client.transaction(*id);
                // TODO: save PeerCache somewhere.
                client
                    .add_commands(&mut trx, sink, &cmds)
                    .context("unable to add received commands")?;
                client.commit(&mut trx, sink).context("commit failed")?;
                // TODO: Update heads
                // client.update_heads(
                //     id,
                //     cmds.iter().filter_map(|cmd| cmd.address().ok()),
                //     heads,
                // )?;
                debug!("committed");
            }
        }

        Ok(())
    }
}

/// The Aranya QUIC sync server.
/// Used to listen for incoming `SyncRequests` and respond with `SyncResponse` when they are received.
#[derive_where(Debug)]
pub struct Server<EN, SP> {
    /// Thread-safe Aranya client reference.
    aranya: AranyaClient<EN, SP>,
    /// QUIC server to handle sync requests and send sync responses.
    server: QuicServer,
    /// Receives updates for the "active team".
    /// Used to ensure that the chosen PSK corresponds to an incoming sync request.
    active_team_rx: mpsc::Receiver<TeamId>,
}

impl<EN, SP> Server<EN, SP> {
    /// Returns the local address the sync server bound to.
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.server.local_addr()?)
    }
}

impl<EN, SP> Server<EN, SP>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    /// Creates a new `Server`.
    #[inline]
    #[allow(deprecated)]
    pub async fn new(
        aranya: AranyaClient<EN, SP>,
        addr: &Addr,
        server_keys: Arc<dyn SelectsPresharedKeys>,
        active_team_rx: mpsc::Receiver<TeamId>,
    ) -> SyncResult<Self> {
        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertResolver::default()));
        server_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        server_config.preshared_keys = PresharedKeySelection::Required(server_keys);

        let tls_server_provider = rustls_provider::Server::new(server_config);

        let addr = tokio::net::lookup_host(addr.to_socket_addrs())
            .await
            .context("DNS lookup on for peer address")?
            .next()
            .assume("invalid server address")?;
        // Use the rustls server provider
        let server = QuicServer::builder()
            .with_tls(tls_server_provider)
            .context("can't set sync server tls config")
            .map_err(Error::ServerConfig)? // Use the wrapped server config
            .with_io(addr)
            .assume("can set sync server addr")
            .map_err(Error::Bug)?
            .with_congestion_controller(Bbr::default())
            .context("can't set congestion controller config")
            .map_err(Error::ServerConfig)?
            .start()
            .context("can't start QUIC server")?;

        Ok(Self {
            aranya,
            server,
            active_team_rx,
        })
    }

    /// Begins accepting incoming requests.
    #[instrument(skip_all, fields(addr = ?self.local_addr()))]
    pub async fn serve(mut self) {
        info!("QUIC sync server listening for incoming connections");

        scope(async |s| {
            // Accept incoming QUIC connections
            while let Some(mut conn) = self.server.accept().await {
                debug!("received incoming QUIC connection");

                let Ok(active_team) = self.active_team_rx.try_recv() else {
                    warn!("no active team for accepted connection");
                    continue;
                };

                let Ok(peer) = conn.remote_addr() else {
                    error!("unable to get peer address from connection");
                    continue;
                };

                let client = self.aranya.clone();

                s.spawn(async move {
                    loop {
                        // Accept incoming streams.
                        match conn.accept_bidirectional_stream().await {
                            Ok(Some(stream)) => {
                                debug!(?peer, "received incoming QUIC stream");
                                if let Err(e) =
                                    Self::sync(client.clone(), peer, stream, &active_team).await
                                {
                                    error!(?e, ?peer, "server unable to sync with peer");
                                    break;
                                }
                            }
                            Ok(None) => {
                                debug!(?peer, "QUIC connection was closed");
                                return;
                            }
                            Err(e) => {
                                error!(?peer, "error receiving QUIC stream: {}", e);
                                return;
                            }
                        }
                    }
                });
            }
        })
        .await;

        error!("server terminated");
    }

    /// Responds to a sync.
    #[instrument(skip_all, fields(peer = %peer))]
    pub async fn sync(
        client: AranyaClient<EN, SP>,
        peer: SocketAddr,
        stream: BidirectionalStream,
        active_team: &TeamId,
    ) -> SyncResult<()> {
        info!(?peer, "server received a sync request");

        let mut recv_buf = Vec::new();
        let (mut recv, mut send) = stream.split();
        recv.read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync request")?;
        debug!(?peer, n = recv_buf.len(), "received sync request");

        // Generate a sync response for a sync request.
        let sync_response_res = Self::sync_respond(client, &recv_buf, active_team)
            .await
            .inspect_err(|e| error!(?e, "error responding to sync request"));

        let resp = match sync_response_res {
            Ok(data) => SyncResponse::Ok(data),
            Err(err) => SyncResponse::Err(format!("{err:?}")),
        };
        // Serialize the sync response.
        let data =
            postcard::to_allocvec(&resp).context("postcard unable to serialize sync response")?;

        let data_len = data.len();
        send.send(Bytes::from(data))
            .await
            .context("Could not send sync response")?;
        send.close().await.map_err(Error::from)?;
        debug!(?peer, n = data_len, "server sent sync response");

        Ok(())
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(
        client: AranyaClient<EN, SP>,
        request_data: &[u8],
        active_team: &TeamId,
    ) -> SyncResult<Box<[u8]>> {
        info!("server responding to sync request");

        // TODO: Use real server address
        let server_address = ();
        let mut resp = SyncResponder::new(server_address);

        let SyncType::Poll {
            request: request_msg,
            address: (),
        } = postcard::from_bytes(request_data).map_err(|e| anyhow::anyhow!(e))?
        else {
            bug!("Other sync types are not implemented");
        };

        check_request(active_team, &request_msg)?;

        resp.receive(request_msg).context("sync recv failed")?;

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        // TODO: save PeerCache somewhere.
        let len = resp
            .poll(
                &mut buf,
                client.lock().await.provider(),
                &mut PeerCache::new(),
            )
            .or_else(|err| {
                if matches!(
                    err,
                    aranya_runtime::SyncError::Storage(StorageError::NoSuchStorage)
                ) {
                    warn!("missing requested graph, we likely have not synced yet");
                    Ok(0)
                } else {
                    Err(err)
                }
            })
            .context("sync resp poll failed")?;
        debug!(len = len, "sync poll finished");
        buf.truncate(len);
        Ok(buf.into())
    }
}

fn check_request(team_id: &TeamId, request: &SyncRequestMessage) -> SyncResult<()> {
    let SyncRequestMessage::SyncRequest { storage_id, .. } = request else {
        bug!("Should be a SyncRequest")
    };
    if team_id.as_bytes() != storage_id.as_bytes() {
        return Err(SyncError::QuicSync(Error::InvalidPSK));
    }

    Ok(())
}
