//! AQC support.

use std::{
    collections::{hash_map::Entry, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use ::rustls::{
    client::PresharedKeyStore,
    crypto::PresharedKey,
    server::{PresharedKeySelection, SelectsPresharedKeys},
    ClientConfig, ServerConfig,
};
use anyhow::Context;
use aranya_crypto::aqc::{BidiChannelId, UniChannelId};
pub use aranya_daemon_api::{AqcBidiChannelId, AqcUniChannelId};
use aranya_daemon_api::{DaemonApiClient, DeviceId, LabelId, NetIdentifier, TeamId};
use buggy::BugExt as _;
use rustls::crypto::CryptoProvider;
use rustls_pemfile::{certs, private_key};
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

/// TODO: remove this.
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!("./cert.pem");
/// TODO: remove this.
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static KEY_PEM: &str = include_str!("./key.pem");

/// ALPN protocol identifier for Aranya QUIC Channels
const ALPN_AQC: &[u8] = b"aqc";

// Define constant PSK identity and bytes
pub const PSK_IDENTITY_CTRL: &[u8; 16] = b"aranya-ctrl-psk!"; // 16 bytes
pub const PSK_BYTES_CTRL: &[u8; 32] = b"this-is-a-32-byte-secret-psk!!!!"; // 32 bytes

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
        // Load Cert and Key
        let certs = certs(&mut CERT_PEM.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to load CERT_PEM")
            .map_err(|e| AqcError::TlsConfig(e.to_string()))?;
        let key = private_key(&mut KEY_PEM.as_bytes())
            .context("Failed to load KEY_PEM")
            .map_err(|e| AqcError::TlsConfig(e.to_string()))?
            .ok_or_else(|| AqcError::TlsConfig("No private key found in KEY_PEM".into()))?;

        let psk = PresharedKey::external(PSK_IDENTITY_CTRL, PSK_BYTES_CTRL)
            .assume("unable to create psk")?;
        let client_keys = Arc::new(ClientPresharedKeys::new(psk.clone()));

        // Create Client Config (INSECURE: Skips server cert verification)
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_AQC.to_vec()]; // Set field directly
        client_config.preshared_keys = client_keys.clone(); // Pass the Arc<ClientPresharedKeys>

        let (mut server_keys, identity_rx) = ServerPresharedKeys::new();
        server_keys.insert(psk);

        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .map_err(|e| AqcError::TlsConfig(e.to_string()))?;
        server_config.alpn_protocols = vec![ALPN_AQC.to_vec()]; // Set field directly
        server_config.preshared_keys = PresharedKeySelection::Enabled(Arc::new(server_keys));

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
        id: BidiChannelId,
        psk: PresharedKey,
    ) -> Result<AqcBidirectionalChannel, AqcError> {
        self.client
            .create_bidi_channel(peer_addr, label_id, id, psk)
            .await
            .map_err(AqcError::Other)
    }

    /// Creates a unidirectional AQC channel with a peer.
    pub async fn create_unidirectional_channel(
        &mut self,
        peer_addr: SocketAddr,
        label_id: LabelId,
        id: UniChannelId,
        psk: PresharedKey,
    ) -> Result<AqcSenderChannel, AqcError> {
        self.client
            .create_uni_channel(peer_addr, label_id, id, psk)
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
        self.identity_sender
            .try_send(identity.to_vec())
            .expect("Failed to send identity");

        key
    }
}

#[derive(Debug)]
pub(crate) struct ClientPresharedKeys {
    key_ref: Arc<Mutex<Arc<PresharedKey>>>,
}

impl ClientPresharedKeys {
    fn new(key: PresharedKey) -> Self {
        Self {
            key_ref: Arc::new(Mutex::new(Arc::new(key))),
        }
    }

    pub(crate) fn set_key(&self, key: PresharedKey) {
        let mut key_guard = self.key_ref.lock().expect("Client PSK mutex poisoned");
        *key_guard = Arc::new(key);
    }
}

impl PresharedKeyStore for ClientPresharedKeys {
    fn psks(&self, _server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        let key_guard = self.key_ref.lock().expect("Client PSK mutex poisoned");
        vec![key_guard.clone()]
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

        let (aqc_ctrl, psk) = self
            .client
            .daemon
            .create_aqc_bidi_channel(context::current(), team_id, peer.clone(), label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, psk_ident = ?psk.identity, "created bidi channel");

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
            .create_bidirectional_channel(
                peer_addr,
                label_id,
                psk.identity.into(),
                PresharedKey::external(psk.identity.as_bytes(), psk.secret.raw_secret_bytes())
                    .assume("unable to create psk")?,
            )
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

        let (aqc_ctrl, psk) = self
            .client
            .daemon
            .create_aqc_uni_channel(context::current(), team_id, peer.clone(), label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, psk_ident = ?psk.identity, "created uni channel");

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
        let secret = match psk.secret {
            aranya_daemon_api::Directed::Send(s) => s,
            aranya_daemon_api::Directed::Recv(s) => s,
        };
        let channel = self
            .client
            .aqc
            .create_unidirectional_channel(
                peer_addr,
                label_id,
                psk.identity.into(),
                PresharedKey::external(psk.identity.as_bytes(), secret.raw_secret_bytes())
                    .assume("unable to create psk")?,
            )
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
