//! AQC support.

use std::{
    collections::{hash_map::Entry, HashMap},
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex},
};

use ::rustls::{
    client::PresharedKeyStore,
    crypto::PresharedKey,
    server::{PresharedKeySelection, SelectsPresharedKeys},
    ClientConfig, ServerConfig,
};
use aranya_crypto::aqc::{BidiChannelId, UniChannelId};
pub use aranya_daemon_api::{AqcBidiChannelId, AqcUniChannelId};
use aranya_daemon_api::{
    AqcBidiPsks, AqcPsks, AqcUniPsks, CipherSuiteId, DaemonApiClient, DeviceId, Directed, LabelId,
    NetIdentifier, TeamId,
};
use buggy::BugExt as _;
use rustls::crypto::{hash::HashAlgorithm, CryptoProvider};
use s2n_quic::{
    provider::{
        congestion_controller::Bbr,
        tls::rustls::{self as rustls_provider, rustls::pki_types::ServerName},
    },
    Server,
};
use tarpc::context;
use tokio::sync::mpsc;
use tracing::{debug, error, instrument};

use super::net::{AqcSenderChannel, TryReceiveError};
use crate::{
    aqc::net::{AqcBidirectionalChannel, AqcClient, AqcReceiveChannelType},
    error::{aranya_error, AqcError, IpcError},
    Client,
};

/// AQC version.
pub type AqcVersion = u16;

/// Current AQC version.
// TODO: return `VersionMismatch` error if peer version does not match this version.
pub const AQC_VERSION: AqcVersion = 1;

/// ALPN protocol identifier for Aranya QUIC Channels
const ALPN_AQC: &[u8] = b"aqc";

// Define constant PSK identity and bytes
pub(super) const PSK_IDENTITY_CTRL: &[u8; 16] = b"aranya-ctrl-psk!"; // 16 bytes
const PSK_BYTES_CTRL: &[u8; 32] = b"this-is-a-32-byte-secret-psk!!!!"; // 32 bytes

pub(super) static CTRL_KEY: LazyLock<Arc<PresharedKey>> = LazyLock::new(|| {
    let psk = PresharedKey::external(PSK_IDENTITY_CTRL, PSK_BYTES_CTRL)
        .expect("identity and bytes are small and nonzero");
    let psk = psk
        .with_hash_alg(HashAlgorithm::SHA384)
        .expect("valid hash alg");
    Arc::new(psk)
});

#[derive(Debug)]
pub enum AqcChannel {
    Bidirectional { id: BidiChannelId },
    Unidirectional { id: UniChannelId },
}

/// Sends and receives AQC messages.
#[derive(Debug)]
pub(crate) struct AqcChannelsImpl {
    pub(crate) client: AqcClient,
}

impl AqcChannelsImpl {
    /// Creates a new `QuicChannelsImpl` listening for connections on `address`.
    #[allow(deprecated)]
    pub(crate) async fn new(
        device_id: DeviceId,
        aqc_addr: &SocketAddr,
        daemon: Arc<DaemonApiClient>,
    ) -> Result<(Self, SocketAddr), AqcError> {
        debug!("device ID: {:?}", device_id);

        // --- Start Rustls Setup ---
        let client_keys = Arc::new(ClientPresharedKeys::new(CTRL_KEY.clone()));

        // Create Client Config (INSECURE: Skips server cert verification)
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_AQC.to_vec()]; // Set field directly
        client_config.preshared_keys = client_keys.clone(); // Pass the Arc<ClientPresharedKeys>

        // TODO(jdygert): enable after rustls upstream fix.
        // client_config.psk_kex_modes = vec![PskKexMode::PskOnly];

        let (server_keys, identity_rx) = ServerPresharedKeys::new();
        server_keys.insert(CTRL_KEY.clone());
        let server_keys = Arc::new(server_keys);

        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertResolver::default()));
        server_config.alpn_protocols = vec![ALPN_AQC.to_vec()]; // Set field directly
        server_config.preshared_keys =
            PresharedKeySelection::Required(Arc::clone(&server_keys) as _);

        let tls_client_provider = rustls_provider::Client::new(client_config);
        let tls_server_provider = rustls_provider::Server::new(server_config);
        // --- End Rustls Setup ---

        // Use the rustls client provider
        // Pass client_keys Arc to AqcClient::new

        // Use the rustls server provider
        let server = Server::builder()
            .with_tls(tls_server_provider) // Use the wrapped server config
            .map_err(|e| AqcError::TlsConfig(e.to_string()))?
            .with_io(*aqc_addr)
            .map_err(|e| AqcError::IoConfig(e.to_string()))?
            .with_congestion_controller(Bbr::default())
            .map_err(|e| AqcError::CongestionConfig(e.to_string()))?
            .start()
            .map_err(|e| AqcError::ServerStart(e.to_string()))?;
        let client = AqcClient::new(
            tls_client_provider,
            client_keys,
            server_keys,
            identity_rx,
            server,
            daemon,
        )?;
        Ok((Self { client }, *aqc_addr))
    }

    /// Returns the local address that AQC is bound to.
    pub async fn local_addr(&self) -> Result<SocketAddr, AqcError> {
        Ok(self.client.local_addr().await?)
    }

    /// Creates a bidirectional AQC channel with a peer.
    pub async fn create_bidirectional_channel(
        &mut self,
        peer_addr: SocketAddr,
        label_id: LabelId,
        psks: AqcBidiPsks,
    ) -> Result<AqcBidirectionalChannel, AqcError> {
        self.client
            .create_bidi_channel(peer_addr, label_id, psks)
            .await
            .map_err(AqcError::Other)
    }

    /// Creates a unidirectional AQC channel with a peer.
    pub async fn create_unidirectional_channel(
        &mut self,
        peer_addr: SocketAddr,
        label_id: LabelId,
        psks: AqcUniPsks,
    ) -> Result<AqcSenderChannel, AqcError> {
        self.client
            .create_uni_channel(peer_addr, label_id, psks)
            .await
            .map_err(AqcError::Other)
    }

    /// Receives a channel.
    pub async fn receive_channel(&mut self) -> Result<AqcReceiveChannelType, AqcError> {
        self.client.receive_channel().await
    }

    /// Attempts to receive a channel.
    pub fn try_receive_channel(&mut self) -> Result<AqcReceiveChannelType, TryReceiveError> {
        self.client.try_receive_channel()
    }
}

#[derive(Debug)]
pub(crate) struct ServerPresharedKeys {
    keys: Mutex<HashMap<Vec<u8>, Arc<PresharedKey>>>,
    // Optional sender to report the selected identity
    identity_sender: mpsc::Sender<Vec<u8>>,
}

impl ServerPresharedKeys {
    fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        // Create the mpsc channel for PSK identities
        let (identity_tx, identity_rx) = mpsc::channel::<Vec<u8>>(10);

        (
            Self {
                keys: Mutex::default(),
                identity_sender: identity_tx,
            },
            identity_rx,
        )
    }

    fn insert(&self, psk: Arc<PresharedKey>) {
        let identity = psk.identity().to_vec();
        match self.keys.lock().expect("poisoned").entry(identity.clone()) {
            Entry::Vacant(v) => {
                v.insert(psk);
            }
            Entry::Occupied(_) => {
                error!("Duplicate PSK identity inserted: {:?}", identity);
            }
        }
    }

    pub(crate) fn load_psks(&self, psks: AqcPsks) {
        let mut keys = self.keys.lock().expect("poisoned");
        match psks {
            AqcPsks::Bidi(psks) => {
                for (suite, psk) in psks {
                    let key = PresharedKey::external(
                        psk.identity.as_bytes(),
                        psk.secret.raw_secret_bytes(),
                    )
                    .expect("valid psk")
                    .with_hash_alg(suite_hash(suite))
                    .expect("valid hash alg");
                    keys.insert(psk.identity.as_bytes().to_vec(), Arc::new(key));
                }
            }
            AqcPsks::Uni(psks) => {
                for (suite, psk) in psks {
                    let key = PresharedKey::external(
                        psk.identity.as_bytes(),
                        match &psk.secret {
                            Directed::Send(s) => s.raw_secret_bytes(),
                            Directed::Recv(s) => s.raw_secret_bytes(),
                        },
                    )
                    .expect("valid psk")
                    .with_hash_alg(suite_hash(suite))
                    .expect("valid hash alg");
                    keys.insert(psk.identity.as_bytes().to_vec(), Arc::new(key));
                }
            }
        };
    }
}

impl SelectsPresharedKeys for ServerPresharedKeys {
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        self.keys.lock().expect("poisoned").get(identity).cloned()
    }

    fn chosen(&self, identity: &[u8]) {
        // Use try_send for non-blocking behavior.
        self.identity_sender
            .try_send(identity.to_vec())
            .expect("Failed to send identity");
    }
}

#[derive(Debug)]
pub(crate) struct ClientPresharedKeys {
    keys: Arc<Mutex<Vec<Arc<PresharedKey>>>>,
}

impl ClientPresharedKeys {
    fn new(key: Arc<PresharedKey>) -> Self {
        Self {
            keys: Arc::new(Mutex::new(vec![key])),
        }
    }

    pub(crate) fn set_key(&self, key: Arc<PresharedKey>) {
        let mut keys_guard = self.keys.lock().expect("Client PSK mutex poisoned");
        keys_guard.clear();
        keys_guard.push(key);
    }

    pub(crate) fn load_psks(&self, psks: AqcPsks) {
        let keys = match psks {
            AqcPsks::Bidi(psks) => psks
                .into_iter()
                .map(|(suite, psk)| {
                    PresharedKey::external(psk.identity.as_bytes(), psk.secret.raw_secret_bytes())
                        .expect("valid psk")
                        .with_hash_alg(suite_hash(suite))
                        .expect("valid hash alg")
                })
                .map(Arc::new)
                .collect(),
            AqcPsks::Uni(psks) => psks
                .into_iter()
                .map(|(suite, psk)| {
                    let secret = match &psk.secret {
                        Directed::Send(s) => s.raw_secret_bytes(),
                        Directed::Recv(s) => s.raw_secret_bytes(),
                    };
                    PresharedKey::external(psk.identity.as_bytes(), secret)
                        .expect("valid psk")
                        .with_hash_alg(suite_hash(suite))
                        .expect("valid hash alg")
                })
                .map(Arc::new)
                .collect(),
        };
        *self.keys.lock().expect("poisoned") = keys;
    }
}

fn suite_hash(suite: CipherSuiteId) -> HashAlgorithm {
    match suite {
        CipherSuiteId::TlsAes128GcmSha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes256GcmSha384 => HashAlgorithm::SHA384,
        CipherSuiteId::TlsChaCha20Poly1305Sha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes128CcmSha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes128Ccm8Sha256 => HashAlgorithm::SHA256,
        _ => HashAlgorithm::SHA256,
    }
}

impl PresharedKeyStore for ClientPresharedKeys {
    fn psks(&self, _server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        self.keys.lock().expect("Client PSK mutex poisoned").clone()
    }
}

/// Aranya QUIC Channels client that allows for opening and closing channels and
/// sending data between peers.
#[derive(Debug)]
pub struct AqcChannels<'a> {
    client: &'a mut Client,
}

impl<'a> AqcChannels<'a> {
    pub(crate) fn new(client: &'a mut Client) -> Self {
        Self { client }
    }

    /// Returns the address that AQC is bound to. This address is used to
    /// make connections to other peers.
    pub async fn local_addr(&self) -> Result<SocketAddr, AqcError> {
        self.client.aqc.local_addr().await
    }

    /// Creates a bidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label_id))]
    pub async fn create_bidi_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> crate::Result<AqcBidirectionalChannel> {
        debug!("creating bidi channel");

        let (aqc_ctrl, psks) = self
            .client
            .daemon
            .create_aqc_bidi_channel(context::current(), team_id, peer.clone(), label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, num_psks = psks.len(), "created bidi channel");

        let peer_addr = tokio::net::lookup_host(peer.0)
            .await
            .map_err(AqcError::AddrResolution)?
            .next()
            .assume("invalid peer address")?;

        self.client
            .aqc
            .client
            .send_ctrl(peer_addr, aqc_ctrl, team_id)
            .await
            .map_err(AqcError::Other)?;
        let channel = self
            .client
            .aqc
            .create_bidirectional_channel(peer_addr, label_id, psks)
            .await?;
        Ok(channel)
    }

    /// Creates a unidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label_id))]
    pub async fn create_uni_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> crate::Result<AqcSenderChannel> {
        debug!("creating aqc uni channel");

        let (aqc_ctrl, psks) = self
            .client
            .daemon
            .create_aqc_uni_channel(context::current(), team_id, peer.clone(), label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, num_psks = psks.len(), "created uni channel");

        let peer_addr = tokio::net::lookup_host(peer.0)
            .await
            .map_err(AqcError::AddrResolution)?
            .next()
            .assume("invalid peer address")?;

        self.client
            .aqc
            .client
            .send_ctrl(peer_addr, aqc_ctrl, team_id)
            .await
            .map_err(AqcError::Other)?;

        let channel = self
            .client
            .aqc
            .create_unidirectional_channel(peer_addr, label_id, psks)
            .await?;
        Ok(channel)
    }

    /// Deletes an AQC bidi channel.
    /// It is an error if the channel does not exist
    #[instrument(skip_all, fields(?chan))]
    pub async fn delete_bidi_channel(
        &mut self,
        mut chan: AqcBidirectionalChannel,
    ) -> crate::Result<()> {
        // let _ctrl = self
        //     .client
        //     .daemon
        //     .delete_aqc_bidi_channel(context::current(), chan.aqc_id().into_id().into())
        //     .await
        //     .map_err(IpcError::new)?
        //     .map_err(aranya_error)?;
        chan.close();
        Ok(())
    }

    /// Deletes an AQC uni channel.
    /// It is an error if the channel does not exist
    #[instrument(skip_all, fields(?chan))]
    pub async fn delete_uni_channel(&mut self, mut chan: AqcSenderChannel) -> crate::Result<()> {
        // let _ctrl = self
        //     .client
        //     .daemon
        //     .delete_aqc_uni_channel(context::current(), chan.aqc_id().into_id().into())
        //     .await
        //     .map_err(IpcError::new)?
        //     .map_err(aranya_error)?;
        chan.close();
        Ok(())
    }

    /// Waits for a peer to create an AQC channel with this client. Returns
    /// None if channels can no longer be received. If this happens, the
    /// application should be restarted.
    pub async fn receive_channel(&mut self) -> Result<AqcReceiveChannelType, AqcError> {
        self.client.aqc.receive_channel().await
    }

    /// Returns the next available channel. If there is no channel available,
    /// return Empty. If the channel is disconnected, return Disconnected. If disconnected
    /// is returned no channels will be available until the application is restarted.
    pub fn try_receive_channel(&mut self) -> Result<AqcReceiveChannelType, TryReceiveError> {
        self.client.aqc.try_receive_channel()
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
