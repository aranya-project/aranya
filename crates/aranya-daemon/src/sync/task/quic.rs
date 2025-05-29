//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with a rustls PSK.
//! A different PSK will be used for each Aranya team.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use core::net::SocketAddr;
use std::{collections::BTreeMap, future::Future, sync::Arc};

use ::rustls::{server::PresharedKeySelection, ClientConfig, ServerConfig};
use anyhow::{bail, Context, Result as AnyResult};
use aranya_crypto::Rng;
use aranya_runtime::{
    Engine, GraphId, PeerCache, Sink, StorageProvider, SyncRequester, SyncResponder, SyncType,
    MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::Addr;
use buggy::{bug, BugExt as _};
use bytes::Bytes;
use rustls::crypto::CryptoProvider;
use s2n_quic::{
    client::Connect,
    connection::Error as ConnErr,
    provider::{
        congestion_controller::Bbr,
        tls::rustls::{self as rustls_provider, rustls::pki_types::ServerName},
    },
    stream::{BidirectionalStream, ReceiveStream, SendStream},
    Client as QuicClient, Connection, Server as QuicServer,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io::AsyncReadExt,
    sync::{
        broadcast::{error::RecvError, Receiver},
        mpsc,
    },
    task::JoinSet,
};
use tracing::{debug, error, info, instrument};
use version::{check_version, VERSION_ERR};

use super::SyncResponse;
use crate::{
    aranya::Client as AranyaClient,
    sync::{
        prot::SyncProtocol,
        task::{SyncState, Syncer},
        SyncError,
    },
};

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = const {
    use crate::daemon::SYNC_PROTOCOL;

    match SYNC_PROTOCOL {
        SyncProtocol::V1 => b"quic_sync_v1",
    }
};

/// QUIC Syncer Version
const QUIC_SYNC_VERSION: Version = Version::V1;

mod psk;
mod version;

pub(crate) use psk::{delete_psk, get_existing_psks, insert_psk, TeamIdPSKPair};
pub use psk::{ClientPresharedKeys, Msg, ServerPresharedKeys};
pub use version::Version;

/// Data used for sending sync requests and processing sync responses
pub struct State {
    /// QUIC client to make sync requests and handle sync responses.
    client: QuicClient,
    /// Address -> Connection map used for re-using connections
    /// when making outgoing sync requests
    conns: BTreeMap<Addr, Connection>,
}

impl SyncState for State {
    #[allow(clippy::manual_async_fn)]
    /// Syncs with the peer.
    /// Aranya client sends a `SyncRequest` to peer then processes the `SyncResponse`.
    fn sync_impl<S>(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> impl Future<Output = AnyResult<()>> + Send
    where
        S: Sink<<crate::EN as Engine>::Effect> + Send,
    {
        async move {
            let stream = syncer.connect(peer).await?;
            // TODO: spawn a task for send/recv?
            let (mut recv, mut send) = stream.split();

            // TODO: Real server address.
            let server_addr = ();
            let mut sync_requester = SyncRequester::new(id, &mut Rng, server_addr);

            // send sync request.
            syncer
                .send_sync_request(&mut send, &mut sync_requester, peer)
                .await?;

            // receive sync response.
            syncer
                .receive_sync_response(&mut recv, &mut sync_requester, &id, sink, peer)
                .await?;

            Ok(())
        }
    }
}

impl State {
    /// Creates a new instance
    pub fn new<I>(initial_keys: I, mut recv: Receiver<Msg>) -> AnyResult<Self>
    where
        I: IntoIterator<Item = TeamIdPSKPair>,
    {
        let client_keys = Arc::new(ClientPresharedKeys::new(initial_keys));

        // Create Client Config (INSECURE: Skips server cert verification)
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        client_config.preshared_keys = client_keys.clone(); // Pass the Arc<ClientPresharedKeys>

        // Client builder doesn't support adding preshared keys
        #[allow(deprecated)]
        let provider = rustls_provider::Client::new(client_config);

        let client = QuicClient::builder()
            .with_tls(provider)?
            .with_io("0.0.0.0:0")?
            .start()?;

        tokio::spawn(async move {
            loop {
                match recv.recv().await {
                    Ok(msg) => client_keys.handle_msg(msg),
                    Err(RecvError::Closed) => break,
                    Err(err) => {
                        error!(err = ?err, "unable to receive psk on broadcast channel")
                    }
                }
            }

            info!("PSK broadcast channel closed");
        });

        Ok(Self {
            client,
            conns: BTreeMap::new(),
        })
    }
}

impl Syncer<State> {
    async fn connect(&mut self, peer: &Addr) -> AnyResult<BidirectionalStream> {
        info!(?peer, "client connecting to QUIC sync server");
        // Check if there is an existing connection with the peer.
        // If not, create a new connection.
        let conns = &mut self.state.conns;
        let client = &self.state.client;
        if !conns.contains_key(peer) {
            debug!(?peer, "existing quic connection not found");

            let addr = tokio::net::lookup_host(peer.to_socket_addrs())
                .await?
                .next()
                .assume("invalid peer address")?;
            // Note: cert is not used but server name must be set to connect.
            debug!(?peer, "attempting to create new quic connection");
            let mut conn = client
                .connect(Connect::new(addr).with_server_name("127.0.0.1"))
                .await?;
            conn.keep_alive(true)?;
            debug!(?peer, "created new quic connection");
            conns.insert(*peer, conn);
        } else {
            debug!("client is able to reuse existing quic connection");
        }

        let Some(conn) = conns.get(peer) else {
            error!(?peer, "unable to lookup quic connection");
            bail!("unable to get connection");
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
            Err(ConnErr::StatelessReset { .. })
            | Err(ConnErr::StreamIdExhausted { .. })
            | Err(ConnErr::MaxHandshakeDurationExceeded { .. }) => {
                bail!("unable to open bidi stream");
            }
            // Other errors means the stream has closed
            Err(e) => {
                conns.remove(peer);
                bail!("connection closed: {e}");
            }
        };

        info!(?peer, "client opened bidi stream with QUIC sync server");
        Ok(stream)
    }

    async fn send_sync_request<A>(
        &self,
        send: &mut SendStream,
        syncer: &mut SyncRequester<'_, A>,
        peer: &Addr,
    ) -> AnyResult<()>
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

        // TODO: `send_all`?
        send.send(Bytes::from_owner([QUIC_SYNC_VERSION as u8]))
            .await?;
        send.send(Bytes::from_owner(send_buf)).await?;
        send.close().await?;
        debug!(?peer, "sent sync request");

        Ok(())
    }

    async fn receive_sync_response<S, A>(
        &self,
        recv: &mut ReceiveStream,
        syncer: &mut SyncRequester<'_, A>,
        id: &GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> AnyResult<()>
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

        // check sync version
        let Some((version_byte, sync_response)) = recv_buf.split_first() else {
            error!("Empty sync response");
            bail!("Empty sync response");
        };
        check_version(*version_byte, QUIC_SYNC_VERSION)?;

        // process the sync response.
        let resp = postcard::from_bytes(sync_response)
            .context("postcard unable to deserialize sync response")?;
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => bail!("sync error: {msg}"),
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
pub struct Server<EN, SP> {
    /// Thread-safe Aranya client reference.
    aranya: AranyaClient<EN, SP>,
    /// QUIC server to handle sync requests and send sync responses.
    server: QuicServer,
    /// Tracks running tasks.
    set: JoinSet<()>,
    /// Identity Receiver.
    _identity_rx: mpsc::Receiver<Vec<u8>>,
}

impl<EN, SP> Server<EN, SP> {
    /// Returns the local address the sync server bound to.
    pub fn local_addr(&self) -> AnyResult<SocketAddr> {
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
    pub async fn new<I>(
        aranya: AranyaClient<EN, SP>,
        addr: &Addr,
        initial_psks: I,
        mut recv: Receiver<Msg>,
    ) -> AnyResult<Self>
    where
        I: IntoIterator<Item = TeamIdPSKPair>,
    {
        let (server_keys, _identity_rx) = ServerPresharedKeys::new();
        let server_keys = Arc::new(server_keys);
        server_keys.extend(initial_psks)?;

        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertResolver::default()));
        server_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        server_config.preshared_keys = PresharedKeySelection::Required(server_keys.clone());

        let tls_server_provider = rustls_provider::Server::new(server_config);

        let addr = tokio::net::lookup_host(addr.to_socket_addrs())
            .await?
            .next()
            .assume("invalid server address")?;
        // Use the rustls server provider
        let server = QuicServer::builder()
            .with_tls(tls_server_provider)? // Use the wrapped server config
            .with_io(addr)?
            .with_congestion_controller(Bbr::default())?
            .start()?;

        let mut set = JoinSet::new();

        set.spawn(async move {
            loop {
                match recv.recv().await {
                    Ok(msg) => server_keys.handle_msg(msg),
                    Err(RecvError::Closed) => break,
                    Err(err) => {
                        error!(err = ?err, "unable to receive psk on broadcast channel")
                    }
                }
            }

            info!("PSK broadcast channel closed");
        });

        Ok(Self {
            aranya,
            server,
            set,
            _identity_rx,
        })
    }

    /// Begins accepting incoming requests.
    #[instrument(skip_all)]
    pub async fn serve(mut self) -> AnyResult<()> {
        info!(
            "QUIC sync server listening for incoming connections: {}",
            self.local_addr()?
        );

        // Accept incoming QUIC connections
        while let Some(mut conn) = self.server.accept().await {
            debug!("received incoming QUIC connection");
            let Ok(peer) = conn.remote_addr() else {
                error!("unable to get peer address from connection");
                continue;
            };
            let client = self.aranya.clone();
            self.set.spawn(async move {
                loop {
                    // Accept incoming streams.
                    match conn.accept_bidirectional_stream().await {
                        Ok(Some(stream)) => {
                            debug!(?peer, "received incoming QUIC stream");
                            if let Err(e) = Self::sync(client.clone(), peer, stream).await {
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
        error!("server terminated: {}", self.local_addr()?);
        Ok(())
    }

    /// Responds to a sync.
    #[instrument(skip_all, fields(peer = %peer))]
    pub async fn sync(
        client: AranyaClient<EN, SP>,
        peer: SocketAddr,
        stream: BidirectionalStream,
    ) -> AnyResult<()> {
        info!(?peer, "server received a sync request");

        let mut recv_buf = Vec::new();
        let (mut recv, mut send) = stream.split();
        recv.read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync request")?;
        debug!(?peer, n = recv_buf.len(), "received sync request");

        // Generate a sync response for a sync request.
        let sync_response_res = Self::sync_respond(client, &recv_buf)
            .await
            .inspect_err(|e| error!(?e, "error responding to sync request"));

        let resp = match sync_response_res {
            Ok(data) => SyncResponse::Ok(data),
            Err(SyncError::Version) => {
                send.send(Bytes::from_owner([VERSION_ERR])).await?;
                send.close().await?;
                return Ok(());
            }
            Err(err) => SyncResponse::Err(format!("{err:?}")),
        };
        // Serialize the sync response.
        let data =
            postcard::to_allocvec(&resp).context("postcard unable to serialize sync response")?;

        // TODO: `send_all`?
        let data_len = data.len();
        send.send(Bytes::from_owner([QUIC_SYNC_VERSION as u8]))
            .await?;
        send.send(Bytes::from_owner(data)).await?;
        send.close().await?;
        debug!(?peer, n = data_len, "server sent sync response");

        Ok(())
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(
        client: AranyaClient<EN, SP>,
        request_data: &[u8],
    ) -> Result<Box<[u8]>, SyncError> {
        info!("server responding to sync request");

        // Check sync version
        let Some((version_byte, sync_request)) = request_data.split_first() else {
            error!("Empty sync request");
            return Err(anyhow::anyhow!("Empty sync request").into());
        };
        check_version(*version_byte, QUIC_SYNC_VERSION)?;

        // TODO: Use real server address
        let server_address = ();
        let mut resp = SyncResponder::new(server_address);

        let SyncType::Poll {
            request: request_msg,
            address: (),
        } = postcard::from_bytes(sync_request).map_err(|e| anyhow::anyhow!(e))?
        else {
            bug!("Other sync types are not implemented");
        };

        resp.receive(request_msg).context("sync recv failed")?;

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        // TODO: save PeerCache somewhere.
        let len = resp
            .poll(
                &mut buf,
                client.lock().await.provider(),
                &mut PeerCache::new(),
            )
            .context("sync resp poll failed")?;
        debug!(len = len, "sync poll finished");
        buf.truncate(len);
        Ok(buf.into())
    }
}

// --- Start SkipServerVerification ---
// INSECURE: Allows connecting to any server certificate.
// Requires the `dangerous_configuration` feature on the `rustls` crate.
// Use full paths for traits and types
// TODO: remove this once we have a way to exclusively use PSKs.
// Currently, we use this to allow the server to be set up to use PSKs
// without having to rely on the server certificate.

#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    #![allow(clippy::expect_used)]
    fn new() -> Arc<Self> {
        // TODO: don't panic here
        let provider = CryptoProvider::get_default().expect("Default crypto provider not found");
        Arc::new(Self(provider.clone()))
    }
}

// Use full trait path
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> AnyResult<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> AnyResult<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Use the selected provider's verification algorithms
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> AnyResult<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Use the selected provider's verification algorithms
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
// --- End SkipServerVerification ---

// TODO: Move into util crate?
// crates/aranya-client/src/aqc/crypto.rs
#[derive(Debug, Default)]
struct NoCertResolver(Arc<NoSigningKey>);
impl rustls::server::ResolvesServerCert for NoCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::new(rustls::sign::CertifiedKey::new(
            vec![],
            Arc::clone(&self.0) as _,
        )))
    }
}

#[derive(Debug, Default)]
struct NoSigningKey;
impl rustls::sign::SigningKey for NoSigningKey {
    fn choose_scheme(
        &self,
        _offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        None
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}
