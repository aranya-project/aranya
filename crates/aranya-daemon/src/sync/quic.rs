//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with a rustls PSK.
//! A different PSK will be used for each Aranya team.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use core::{fmt, marker::PhantomData, net::SocketAddr};
use std::{collections::BTreeMap, sync::Arc};

use ::rustls::{ClientConfig, ServerConfig};
use anyhow::{bail, Result};
use aranya_policy_ifgen::VmEffect;
use aranya_runtime::{ClientState, Engine, GraphId, Sink, StorageProvider, VmPolicy};
use aranya_util::Addr;
use rustls::crypto::CryptoProvider;
use rustls_pemfile::{certs, private_key};
use s2n_quic::{
    client::Connect,
    provider::{
        congestion_controller::Bbr,
        tls::rustls::{self as rustls_provider, rustls::pki_types::ServerName},
    },
    stream::ReceiveStream,
    Client as QuicClient, Connection, Server as QuicServer,
};
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, task::JoinSet};
use tracing::{debug, error, info, instrument, trace};

use super::prot::SyncProtocols;

/// QUIC Syncer protocol type.
pub const PROT: SyncProtocols = SyncProtocols::QUIC;

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic_sync";

/// QUIC Syncer protocol version.
pub const VERSION: u16 = 1;

// TODO: get this PSK from keystore or config file.
// PSK is hard-coded to prototype the QUIC syncer until PSK key management is complete.
const PSK: &[u8] = "test_psk".as_bytes();

/// TODO: remove this.
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!("./cert.pem");
/// TODO: remove this.
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static KEY_PEM: &str = include_str!("./key.pem");

/// A response to a sync request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResponse {
    /// Success.
    Ok(Box<[u8]>),
    /// Failure.
    Err(String),
}

/// Aranya QUIC sync client.
pub struct Client<EN, SP, CE> {
    /// Thread-safe Aranya client reference.
    pub(crate) aranya: Arc<Mutex<ClientState<EN, SP>>>,
    /// QUIC client to make sync requests and handle sync responses.
    client: Arc<Mutex<QuicClient>>,
    conns: Arc<Mutex<BTreeMap<Addr, Connection>>>,
    _eng: PhantomData<CE>,
}

impl<EN, SP, CE> Client<EN, SP, CE> {
    /// Creates a new [`Client`].
    #[allow(deprecated)]
    pub fn new(aranya: Arc<Mutex<ClientState<EN, SP>>>) -> Result<Self> {
        // Load Cert and Key
        let certs = certs(&mut CERT_PEM.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let key = private_key(&mut KEY_PEM.as_bytes())?;

        // Create Client Config (INSECURE: Skips server cert verification)
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        //client_config.preshared_keys = client_keys.clone(); // Pass the Arc<ClientPresharedKeys>

        // TODO: configure PSKs

        let provider = rustls_provider::Client::new(client_config);

        let client = QuicClient::builder()
            .with_tls(provider)?
            .with_io("0.0.0.0:0")?
            .start()?;

        Ok(Client {
            aranya,
            client: Arc::new(Mutex::new(client)),
            conns: Arc::new(Mutex::new(BTreeMap::new())),
            _eng: PhantomData,
        })
    }
}

impl<EN, SP, CE> Client<EN, SP, CE>
where
    EN: Engine<Policy = VmPolicy<CE>, Effect = VmEffect> + Send + 'static,
    SP: StorageProvider + Send + 'static,
    CE: aranya_crypto::Engine + Send + Sync + 'static,
{
    /// Syncs with the peer.
    /// Aranya client sends a `SyncRequest` to peer then processes the `SyncResponse`.
    #[instrument(skip_all)]
    pub async fn sync_peer<S>(&self, id: GraphId, sink: &mut S, peer: &Addr) -> Result<()>
    where
        S: Sink<<EN as Engine>::Effect>,
    {
        // Check if there is an existing connection with the peer.
        // If not, create a new connection.
        let mut conns = self.conns.lock().await;
        let client = self.client.lock().await;
        if !conns.contains_key(peer) {
            let Some(addr) = peer.lookup().await?.next() else {
                bail!("unable to lookup peer address");
            };
            let conn = client.connect(Connect::new(addr)).await?;
            conns.insert(*peer, conn);
        }

        let Some(_conn) = conns.get(peer) else {
            bail!("unable to get connection");
        };

        Ok(())
    }
}

impl<EN, SP, CE> fmt::Debug for Client<EN, SP, CE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
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
}

impl<EN, SP> Server<EN, SP> {
    /// Creates a new `Server`.
    #[inline]
    #[allow(deprecated)]
    pub async fn new(aranya: Arc<Mutex<ClientState<EN, SP>>>, addr: &Addr) -> Result<Self> {
        // Load Cert and Key
        let certs = certs(&mut CERT_PEM.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let key = private_key(&mut KEY_PEM.as_bytes())?.unwrap();

        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)?;
        server_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        //server_config.preshared_keys = PresharedKeySelection::Enabled(Arc::new(server_keys));

        // TODO: configure PSKs

        let tls_server_provider = rustls_provider::Server::new(server_config);

        let Some(addr) = addr.lookup().await?.into_iter().next() else {
            bail!("unable to lookup server address");
        };
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
        // Accept incoming QUIC connections
        while let Some(mut conn) = self.server.accept().await {
            info!("received incoming QUIC connection");
            let Ok(peer) = conn.remote_addr() else {
                error!("unable to get peer address from connection");
                continue;
            };
            let client = Arc::clone(&self.aranya);
            self.set.spawn(async move {
                loop {
                    // Accept incoming streams.
                    match conn.accept_receive_stream().await {
                        Ok(Some(stream)) => {
                            trace!("received incoming QUIC stream");
                            if let Err(e) = Self::sync(client.clone(), peer, stream).await {
                                error!(?e, ?peer, "unable to sync with peer");
                                break;
                            }
                        }
                        Ok(None) => {
                            debug!("QUIC connection was closed");
                            return;
                        }
                        Err(e) => {
                            error!("error receiving QUIC stream: {}", e);
                            return;
                        }
                    }
                }
            });
        }
        error!("server terminated");
        Ok(())
    }

    /// Responds to a sync.
    #[instrument(skip_all, fields(peer = %peer))]
    async fn sync(
        client: Arc<Mutex<ClientState<EN, SP>>>,
        peer: SocketAddr,
        stream: ReceiveStream,
    ) -> Result<()> {
        todo!();
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(
        client: Arc<Mutex<ClientState<EN, SP>>>,
        request: &[u8],
    ) -> Result<Box<[u8]>> {
        todo!();
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
    fn new() -> Arc<Self> {
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
