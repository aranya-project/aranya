//! AQC support.

use std::{net::SocketAddr, sync::Arc};

use aranya_crypto::aqc::{BidiChannelId, UniChannelId};
use aranya_daemon_api::{
    AqcBidiPsks, AqcUniPsks, DaemonApiClient, DeviceId, LabelId, NetIdentifier, TeamId,
};
use buggy::{Bug, BugExt as _};
use rustls::{server::PresharedKeySelection, ClientConfig, ServerConfig};
use s2n_quic::{
    provider::{
        congestion_controller::Bbr,
        tls::rustls::{self as rustls_provider},
    },
    Server,
};
use tarpc::context;
use tracing::{debug, instrument};

use super::{
    crypto::{
        ClientPresharedKeys, NoCertResolver, ServerPresharedKeys, SkipServerVerification, CTRL_PSK,
    },
    net::{AqcClient, TryReceiveError},
    AqcBidiChannel, AqcPeerChannel, AqcSenderChannel,
};
use crate::{
    error::{aranya_error, no_addr, AqcError, IpcError},
    Client,
};

/// AQC version.
pub type AqcVersion = u16;

/// Current AQC version.
// TODO: return `VersionMismatch` error if peer version does not match this version.
pub const AQC_VERSION: AqcVersion = 1;

/// ALPN protocol identifier for Aranya QUIC Channels
const ALPN_AQC: &[u8] = b"aqc-v1";

#[derive(Copy, Clone, Debug)]
pub enum AqcChannelId {
    Bidi(BidiChannelId),
    Uni(UniChannelId),
}

/// Sends and receives AQC messages.
#[derive(Debug)]
pub(crate) struct AqcChannelsImpl {
    client: AqcClient,
}

impl AqcChannelsImpl {
    /// Creates a new [`AqcChannelsImpl`] listening for connections on `server_addr`.
    pub(crate) async fn new(
        device_id: DeviceId,
        server_addr: SocketAddr,
        daemon: DaemonApiClient,
    ) -> Result<Self, AqcError> {
        debug!("device ID: {:?}", device_id);

        // --- Start Rustls Setup ---
        let client_keys = Arc::new(ClientPresharedKeys::new(CTRL_PSK.clone()));

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
        server_keys.insert(CTRL_PSK.clone());
        let server_keys = Arc::new(server_keys);

        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertResolver::default()));
        server_config.alpn_protocols = vec![ALPN_AQC.to_vec()]; // Set field directly
        server_config.preshared_keys =
            PresharedKeySelection::Required(Arc::clone(&server_keys) as _);

        #[allow(deprecated)]
        let tls_client_provider = rustls_provider::Client::new(client_config);
        #[allow(deprecated)]
        let tls_server_provider = rustls_provider::Server::new(server_config);
        // --- End Rustls Setup ---

        // Use the rustls client provider
        // Pass client_keys Arc to AqcClient::new

        // Use the rustls server provider
        let server = Server::builder()
            .with_tls(tls_server_provider)? // Use the wrapped server config
            .with_io(server_addr)
            .assume("can set aqc server addr")?
            .with_congestion_controller(Bbr::default())?
            .start()
            .map_err(AqcError::ServerStart)?;
        let client = AqcClient::new(
            tls_client_provider,
            client_keys,
            server_keys,
            identity_rx,
            server,
            daemon,
        )?;
        Ok(Self { client })
    }

    /// Returns the local address that the AQC client is bound to.
    pub fn client_addr(&self) -> Result<SocketAddr, Bug> {
        self.client.client_addr()
    }

    /// Returns the local address that the AQC server is bound to.
    pub fn server_addr(&self) -> Result<SocketAddr, Bug> {
        self.client.server_addr()
    }

    /// Creates a bidirectional AQC channel with a peer.
    pub async fn create_bidirectional_channel(
        &mut self,
        peer_addr: SocketAddr,
        label_id: LabelId,
        psks: AqcBidiPsks,
    ) -> Result<AqcBidiChannel, AqcError> {
        self.client
            .create_bidi_channel(peer_addr, label_id, psks)
            .await
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
    }

    /// Receives a channel.
    pub async fn receive_channel(&mut self) -> crate::Result<AqcPeerChannel> {
        self.client.receive_channel().await
    }

    /// Attempts to receive a channel.
    pub fn try_receive_channel(&mut self) -> Result<AqcPeerChannel, TryReceiveError<crate::Error>> {
        self.client.try_receive_channel()
    }
}

/// Aranya QUIC Channels client for managing channels which allow sending and
/// receiving data with peers.
#[derive(Debug)]
pub struct AqcChannels<'a> {
    client: &'a mut Client,
}

impl<'a> AqcChannels<'a> {
    pub(crate) fn new(client: &'a mut Client) -> Self {
        Self { client }
    }

    /// Returns the address that the AQC client is bound to. This address is used to
    /// make connections to other peers.
    pub fn client_addr(&self) -> Result<SocketAddr, AqcError> {
        Ok(self.client.aqc.client_addr()?)
    }

    /// Returns the address that the AQC server is bound to. This address is used by
    /// peers to connect to this instance.
    pub fn server_addr(&self) -> Result<SocketAddr, AqcError> {
        Ok(self.client.aqc.server_addr()?)
    }

    /// Creates a bidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// This method is NOT cancellation safe. Cancelling the resulting future might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label_id))]
    pub async fn create_bidi_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> crate::Result<AqcBidiChannel> {
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
            .ok_or_else(no_addr)?;

        self.client
            .aqc
            .client
            .send_ctrl(peer_addr, aqc_ctrl, team_id)
            .await?;
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
    /// This method is NOT cancellation safe. Cancelling the resulting future might lose data.
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
            .ok_or_else(no_addr)?;

        self.client
            .aqc
            .client
            .send_ctrl(peer_addr, aqc_ctrl, team_id)
            .await?;

        let channel = self
            .client
            .aqc
            .create_unidirectional_channel(peer_addr, label_id, psks)
            .await?;
        Ok(channel)
    }

    /// Deletes an AQC bidi channel.
    #[instrument(skip_all, fields(?chan))]
    pub async fn delete_bidi_channel(&mut self, mut chan: AqcBidiChannel) -> crate::Result<()> {
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

    /// Waits for a peer to create an AQC channel with this client.
    pub async fn receive_channel(&mut self) -> crate::Result<AqcPeerChannel> {
        self.client.aqc.receive_channel().await
    }

    /// Receive the next available channel.
    ///
    /// If there is no channel available, return Empty.
    /// If the channel is closed, return Closed.
    pub fn try_receive_channel(&mut self) -> Result<AqcPeerChannel, TryReceiveError<crate::Error>> {
        self.client.aqc.try_receive_channel()
    }
}
