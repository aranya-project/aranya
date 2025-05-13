//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with a rustls PSK.
//! A different PSK will be used for each Aranya team.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use core::net::SocketAddr;
use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap},
    sync::{Arc, Mutex as SyncMutex},
};

use ::rustls::{
    client::PresharedKeyStore,
    crypto::PresharedKey,
    server::{PresharedKeySelection, SelectsPresharedKeys},
    ClientConfig, ServerConfig,
};
use anyhow::{bail, Context, Result};
use aranya_crypto::Rng;
use aranya_runtime::{
    ClientState, Engine, GraphId, PeerCache, Sink, StorageProvider, SyncRequester, SyncResponder,
    SyncType, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::Addr;
use buggy::{bug, BugExt as _};
use bytes::Bytes;
use rustls::crypto::CryptoProvider;
use rustls_pemfile::{certs, private_key};
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
    sync::{mpsc, Mutex},
    task::JoinSet,
};
use tracing::{debug, error, info, instrument};

use super::SyncResponse;
use crate::sync::{
    prot::SyncProtocol,
    task::{SyncState, Syncer},
};

/// Protocol Version.
pub const PROT: SyncProtocol = SyncProtocol::V1;

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic_sync";

// TODO: get this PSK from keystore or config file.
// PSK is hard-coded to prototype the QUIC syncer until PSK key management is complete.
// Define constant PSK identity and bytes
/// PSK identity.
pub const PSK_IDENTITY: &[u8; 16] = b"aranya-ctrl-psk!"; // 16 bytes
/// PSK secret bytes.
pub const PSK_BYTES: &[u8; 32] = b"this-is-a-32-byte-secret-psk!!!!"; // 32 bytes

/// TODO: remove this.
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!("./cert.pem");
/// TODO: remove this.
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static KEY_PEM: &str = include_str!("./key.pem");

/// Data used for sending sync requests and processing sync responses
pub struct State {
    /// QUIC client to make sync requests and handle sync responses.
    client: QuicClient,
    /// Address -> Connection map used for re-using connections
    /// when making outgoing sync requests
    conns: BTreeMap<Addr, Connection>,
}

impl SyncState for State {
    /// Syncs with the peer.
    /// Aranya client sends a `SyncRequest` to peer then processes the `SyncResponse`.
    async fn sync_impl<S>(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> Result<()>
    where
        S: Sink<<crate::EN as Engine>::Effect>,
    {
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

impl State {
    /// Creates a new instance
    pub fn new() -> Result<Self> {
        // TODO: don't hard-code PSK.
        let psk = PresharedKey::external(PSK_IDENTITY, PSK_BYTES).assume("unable to create psk")?;
        let client_keys = Arc::new(ClientPresharedKeys::new(psk.clone()));

        // Create Client Config (INSECURE: Skips server cert verification)
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        client_config.preshared_keys = client_keys.clone(); // Pass the Arc<ClientPresharedKeys>

        #[allow(deprecated)] //FIXME(Steve) - temporary for CI build
        let provider = rustls_provider::Client::new(client_config);

        let client = QuicClient::builder()
            .with_tls(provider)?
            .with_io("0.0.0.0:0")?
            .start()?;

        Ok(Self {
            client,
            conns: BTreeMap::new(),
        })
    }
}

impl Syncer<State> {
    async fn connect(&mut self, peer: &Addr) -> Result<BidirectionalStream> {
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

    async fn send_sync_request<'a, A>(
        &self,
        send: &mut SendStream,
        syncer: &mut SyncRequester<'a, A>,
        peer: &Addr,
    ) -> Result<()>
    where
        A: Serialize + DeserializeOwned + Clone,
    {
        info!("client sending sync request to QUIC sync server");
        let mut send_buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        let (len, _) = {
            let mut client = self.client.aranya.lock().await;
            // TODO: save PeerCache somewhere.
            syncer
                .poll(&mut send_buf, client.provider(), &mut PeerCache::new())
                .context("sync poll failed")?
        };
        debug!(?len, "sync poll finished");
        send_buf.truncate(len);

        // TODO: `send_all`?
        send.send(Bytes::from_owner([self.protocol as u8])).await?;
        send.send(Bytes::from_owner(send_buf)).await?;
        send.close().await?;
        debug!(?peer, "sent sync request");

        Ok(())
    }

    async fn receive_sync_response<'a, S, A>(
        &self,
        recv: &mut ReceiveStream,
        syncer: &mut SyncRequester<'a, A>,
        id: &GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> Result<()>
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
            SyncResponse::Err(msg) => bail!("sync error: {msg}"),
        };
        if data.is_empty() {
            debug!("nothing to sync");
            return Ok(());
        }
        if let Some(cmds) = syncer.receive(&data)? {
            debug!(num = cmds.len(), "received commands");
            if !cmds.is_empty() {
                let mut client = self.client.aranya.lock().await;
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
    aranya: Arc<Mutex<ClientState<EN, SP>>>,
    /// QUIC server to handle sync requests and send sync responses.
    server: QuicServer,
    /// Tracks running tasks.
    set: JoinSet<()>,
    /// Identity Receiver.
    _identity_rx: mpsc::Receiver<Vec<u8>>,
    /// Sync Protocol version.
    protocol: SyncProtocol,
}

impl<EN, SP> Server<EN, SP> {
    /// Creates a new `Server`.
    #[inline]
    #[allow(deprecated)]
    pub async fn new(
        aranya: Arc<Mutex<ClientState<EN, SP>>>,
        addr: &Addr,
        protocol: SyncProtocol,
    ) -> Result<Self> {
        // Load Cert and Key
        let certs = certs(&mut CERT_PEM.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let key = private_key(&mut KEY_PEM.as_bytes())?.assume("expected private key")?;

        // TODO: don't hard-code PSK.
        let psk = PresharedKey::external(PSK_IDENTITY, PSK_BYTES).assume("unable to create psk")?;
        let (mut server_keys, _identity_rx) = ServerPresharedKeys::new();
        server_keys.insert(psk);

        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)?;
        server_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        server_config.preshared_keys = PresharedKeySelection::Enabled(Arc::new(server_keys));

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

        Ok(Self {
            aranya,
            server,
            set: JoinSet::new(),
            _identity_rx,
            protocol,
        })
    }

    /// Returns the local address the sync server bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.server.local_addr()?)
    }
}

impl<EN, SP> Server<EN, SP>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    /// Begins accepting incoming requests.
    #[instrument(skip_all)]
    pub async fn serve(mut self) -> Result<()> {
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
            let client = Arc::clone(&self.aranya);
            self.set.spawn(async move {
                loop {
                    // Accept incoming streams.
                    match conn.accept_bidirectional_stream().await {
                        Ok(Some(stream)) => {
                            debug!(?peer, "received incoming QUIC stream");
                            if let Err(e) =
                                Self::sync(client.clone(), peer, stream, self.protocol).await
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
        error!("server terminated: {}", self.local_addr()?);
        Ok(())
    }

    /// Responds to a sync.
    #[instrument(skip_all, fields(peer = %peer))]
    pub async fn sync(
        client: Arc<Mutex<ClientState<EN, SP>>>,
        peer: SocketAddr,
        stream: BidirectionalStream,
        protocol: SyncProtocol,
    ) -> Result<()> {
        info!(?peer, "server received a sync request");

        let mut recv_buf = Vec::new();
        let (mut recv, mut send) = stream.split();
        recv.read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync request")?;
        debug!(?peer, n = recv_buf.len(), "received sync request");

        // Generate a sync response for a sync request.
        let resp = match Self::sync_respond(client, &recv_buf, protocol).await {
            Ok(data) => SyncResponse::Ok(data),
            Err(err) => {
                error!(?err, "error responding to sync request");
                SyncResponse::Err(format!("{err:?}"))
            }
        };
        // Serialize the sync response.
        let data =
            &postcard::to_allocvec(&resp).context("postcard unable to serialize sync response")?;

        // TODO: `send_all`?
        send.send(Bytes::copy_from_slice(data)).await?;
        send.close().await?;
        debug!(?peer, n = data.len(), "server sent sync response");

        Ok(())
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(
        client: Arc<Mutex<ClientState<EN, SP>>>,
        request_data: &[u8],
        protocol: SyncProtocol,
    ) -> Result<Box<[u8]>> {
        info!("server responding to sync request");

        let Some((version, sync_request)) = request_data.split_first() else {
            error!("Empty sync request");
            bail!("Empty sync request");
        };

        debug_assert_eq!(*version, protocol as u8);

        // TODO: Use real server address
        let server_address = ();
        let mut resp = SyncResponder::new(server_address);

        let SyncType::Poll {
            request: request_msg,
            address: (),
        } = postcard::from_bytes(sync_request)?
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

#[derive(Debug)]
struct ServerPresharedKeys {
    keys: HashMap<Vec<u8>, Arc<PresharedKey>>,
    // Optional sender to report the selected identity
    identity_sender: mpsc::Sender<Vec<u8>>,
}

impl ServerPresharedKeys {
    fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        // Create the mpsc channel for PSK identities
        let (identity_tx, identity_rx) = mpsc::channel::<Vec<u8>>(10);

        (
            Self {
                keys: HashMap::new(),
                identity_sender: identity_tx,
            },
            identity_rx,
        )
    }

    fn insert(&mut self, psk: PresharedKey) {
        let identity = psk.identity().to_vec();
        match self.keys.entry(identity.clone()) {
            Entry::Vacant(v) => {
                v.insert(Arc::new(psk));
            }
            Entry::Occupied(_) => {
                error!("Duplicate PSK identity inserted: {:?}", identity);
            }
        }
    }
}

impl SelectsPresharedKeys for ServerPresharedKeys {
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        let key = self.keys.get(identity).cloned();

        // Use try_send for non-blocking behavior. Ignore error if receiver dropped.
        let _ = self
            .identity_sender
            .try_send(identity.to_vec())
            .assume("Failed to send identity");

        key
    }
}

#[derive(Debug)]
pub(crate) struct ClientPresharedKeys {
    key_ref: Arc<SyncMutex<Arc<PresharedKey>>>,
}

impl ClientPresharedKeys {
    fn new(key: PresharedKey) -> Self {
        Self {
            key_ref: Arc::new(SyncMutex::new(Arc::new(key))),
        }
    }

    // TODO: if we need to set PSK to something else
    /*
    pub(crate) fn set_key(&self, key: PresharedKey) {
        let mut key_guard = self.key_ref.lock().expect("Client PSK mutex poisoned");
        *key_guard = Arc::new(key);
    }
    */
}

impl PresharedKeyStore for ClientPresharedKeys {
    #![allow(clippy::expect_used)]
    fn psks(&self, _server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        // TODO: don't panic here
        let key_guard = self.key_ref.lock().expect("Client PSK mutex poisoned");
        vec![key_guard.clone()]
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
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
