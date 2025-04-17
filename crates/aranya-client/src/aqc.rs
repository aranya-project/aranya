//! AQC support.

use std::{io, net::SocketAddr, path::Path};

use anyhow::{anyhow, Context};
use aranya_aqc_util::{
    BidiChannelCreated, BidiChannelReceived, Handler, UniChannelCreated, UniChannelReceived,
};
use aranya_crypto::{
    aqc::{BidiChannelId, BidiPeerEncap, UniChannelId, UniPeerEncap},
    default::DefaultEngine,
    import::Import,
    keys::SecretKey,
    keystore::fs_keystore::Store,
    Rng,
};
pub use aranya_daemon_api::{AqcBidiChannelId, AqcUniChannelId};
use aranya_daemon_api::{
    AqcChannelInfo::*, AqcCtrl, DeviceId, KeyStoreInfo, LabelId, NetIdentifier, TeamId, CS,
};
use aranya_fast_channels::NodeId;
use tarpc::context;
use tokio::{fs, sync::mpsc};
use tracing::{debug, info, instrument, Instrument as _};

use crate::{
    aqc_net::{AqcBidirectionalChannel, AqcChannelType, AqcClient},
    error::AqcError,
};

// TODO: use same generics as daemon.
/// CE = Crypto Engine
pub(crate) type CE = DefaultEngine;
/// KS = Key Store
pub(crate) type KS = Store;

/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!("./cert.pem");
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static KEY_PEM: &str = include_str!("./key.pem");

/// Sends and receives AQC messages.
pub(crate) struct AqcChannelsImpl {
    client: AqcClient,
    client_sender: mpsc::Sender<AqcChannelType>,
    // TODO: add Aqc fields.
    handler: Handler<Store>,
    eng: CE,
}

impl AqcChannelsImpl {
    /// Creates a new `QuicChannelsImpl` listening for connections on `address`.
    pub(crate) async fn new(
        device_id: DeviceId,
        keystore_info: KeyStoreInfo,
    ) -> Result<Self, AqcError> {
        debug!("device ID: {:?}", device_id);
        debug!("keystore path: {:?}", keystore_info.path);
        debug!("keystore wrapped key path: {:?}", keystore_info.wrapped_key);
        let store = KS::open(keystore_info.path).context("unable to open keystore")?;
        let handler = Handler::new(
            device_id.into_id().into(),
            store.try_clone().context("unable to clone keystore")?,
        );
        let eng = {
            let key = load_or_gen_key(keystore_info.wrapped_key).await?;
            CE::new(&key, Rng)
        };

        let (client, sender) = AqcClient::new(CERT_PEM)?;
        Ok(Self {
            client,
            client_sender: sender,
            handler,
            eng,
        })
    }

    /// Returns the sender for the client.
    pub fn get_client_sender(&self) -> mpsc::Sender<AqcChannelType> {
        self.client_sender.clone()
    }

    /// Returns the local address that AQC is bound to.
    pub async fn local_addr(&self) -> Result<SocketAddr, AqcError> {
        Ok(self.client.local_addr().await?)
    }

    pub async fn create_bidirectional_channel(
        &mut self,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> Result<AqcBidirectionalChannel, AqcError> {
        let peer_addr = tokio::net::lookup_host(peer.as_ref())
            .await
            .map_err(anyhow::Error::new)?
            .next()
            .ok_or_else(|| anyhow!("No addresses found for {}", peer))?;

        self.client
            .create_bidirectional_channel(peer_addr, label_id)
            .await
            .map_err(AqcError::Other)
    }

    /// Receives a channel.
    pub async fn receive_channel(&mut self) -> Option<AqcChannelType> {
        self.client.receive_channel().await
    }
}

/// Aranya QUIC Channels client that allows for opening and closing channels and
/// sending data between peers.
pub struct AqcChannels<'a> {
    client: &'a mut crate::Client,
}

impl<'a> AqcChannels<'a> {
    pub(crate) fn new(client: &'a mut crate::Client) -> Self {
        Self { client }
    }

    /// Returns the address that AQC is bound to.
    pub async fn local_addr(&self) -> Result<SocketAddr, AqcError> {
        self.client.aqc.local_addr().await
    }

    /// Returns the sender for the client.
    pub fn get_client_sender(&self) -> mpsc::Sender<AqcChannelType> {
        self.client.aqc.get_client_sender()
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
        peer_addr: NetIdentifier,
        label_id: LabelId,
    ) -> crate::Result<(AqcBidirectionalChannel, AqcCtrl)> {
        debug!("creating bidi channel");

        let node_id: NodeId = 0.into();
        //let node_id = self.client.aqc.get_next_node_id().await?;
        debug!(%node_id, "selected node ID");

        let (aqc_ctrl, aqc_info) = self
            .client
            .daemon
            .create_aqc_bidi_channel(context::current(), team_id, peer.clone(), node_id, label_id)
            .await??;
        debug!(%node_id, %label_id, "created bidi channel");

        if let BidiCreated(v) = aqc_info {
            let effect = BidiChannelCreated {
                parent_cmd_id: v.parent_cmd_id,
                author_id: v.author_id.into_id().into(),
                author_enc_key_id: v.author_enc_key_id,
                peer_id: v.peer_id.into_id().into(),
                peer_enc_pk: &v.peer_enc_pk,
                label_id: v.label_id.into_id().into(),
                channel_id: v.channel_id,
                psk_length_in_bytes: v.psk_length_in_bytes,
                author_secrets_id: v.author_secrets_id,
            };
            let psk = self
                .client
                .aqc
                .handler
                .bidi_channel_created(&mut self.client.aqc.eng.clone(), &effect)
                .map_err(AqcError::ChannelCreation)?;
            debug!("psk id: {:?}", psk.identity());

            // TODO: send ctrl msg via network.
            let channel = self
                .client
                .aqc
                .create_bidirectional_channel(peer_addr, label_id)
                .await?;
            // TODO: for testing only. Send ctrl via network instead of returning.
            Ok((channel, aqc_ctrl))
        } else {
            Err(crate::Error::Aqc(AqcError::Other(anyhow!(
                "unable to create uni channel"
            ))))
        }
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
    ) -> crate::Result<(AqcUniChannelId, AqcCtrl)> {
        debug!("creating aqc uni channel");

        // TODO: use correct node ID.
        let node_id: NodeId = 0.into();
        debug!(%node_id, "selected node ID");

        let (aqc_ctrl, aqc_info) = self
            .client
            .daemon
            .create_aqc_uni_channel(context::current(), team_id, peer.clone(), node_id, label_id)
            .await??;
        debug!(%node_id, %label_id, "created aqc uni channel");

        if let UniCreated(v) = aqc_info {
            let effect = UniChannelCreated {
                parent_cmd_id: v.parent_cmd_id,
                author_id: v.author_id.into_id().into(),
                author_enc_key_id: v.author_enc_key_id,
                send_id: v.send_id.into_id().into(),
                recv_id: v.recv_id.into_id().into(),
                peer_enc_pk: &v.peer_enc_pk,
                label_id: v.label_id.into_id().into(),
                channel_id: v.channel_id,
                psk_length_in_bytes: v.psk_length_in_bytes,
                author_secrets_id: v.author_secrets_id,
            };
            let psk = self
                .client
                .aqc
                .handler
                .uni_channel_created(&mut self.client.aqc.eng.clone(), &effect)
                .map_err(AqcError::ChannelCreation)?;
            debug!("psk id: {:?}", psk.identity());

            // TODO: send ctrl msg via network.

            // TODO: for testing only. Send ctrl via network instead of returning.
            return Ok((v.channel_id.into_id().into(), aqc_ctrl));
        }

        // TODO: clean up error-handling
        Err(crate::Error::Aqc(AqcError::Other(anyhow!(
            "unable to create uni channel"
        ))))
    }

    /// Deletes an AQC bidi channel.
    // It is an error if the channel does not exist
    #[instrument(skip_all, fields(chan = %chan))]
    pub async fn delete_bidi_channel(&mut self, chan: AqcBidiChannelId) -> crate::Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_aqc_bidi_channel(context::current(), chan)
            .await??;
        //self.client.aqc.remove_channel(chan).await;
        Ok(())
    }

    /// Deletes an AQC uni channel.
    // It is an error if the channel does not exist
    #[instrument(skip_all, fields(chan = %chan))]
    pub async fn delete_uni_channel(&mut self, chan: AqcUniChannelId) -> crate::Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_aqc_uni_channel(context::current(), chan)
            .await??;
        //self.client.aqc.remove_channel(chan).await;
        Ok(())
    }

    /// Receives an AQC ctrl message.
    // TODO: this method is pub for testing.
    // In final AQC implementation, it will only be invoked when a ctrl msg is received via the network.
    pub async fn receive_aqc_ctrl(&mut self, team: TeamId, ctrl: AqcCtrl) -> crate::Result<()> {
        // TODO: use correct node ID
        let node_id: NodeId = 0.into();

        let (_peer, aqc_info) = self
            .client
            .daemon
            .receive_aqc_ctrl(context::current(), team, node_id, ctrl)
            .await??;

        match aqc_info {
            BidiReceived(v) => {
                let encap = BidiPeerEncap::<CS>::from_bytes(&v.encap)
                    .context("unable to get encap")
                    .map_err(AqcError::Encap)?;
                let channel_id: BidiChannelId = encap.id();
                let effect = BidiChannelReceived {
                    parent_cmd_id: v.parent_cmd_id,
                    author_id: v.author_id.into_id().into(),
                    author_enc_pk: &v.author_enc_pk,
                    peer_id: v.peer_id.into_id().into(),
                    peer_enc_key_id: v.peer_enc_key_id,
                    label_id: v.label_id.into_id().into(),
                    encap: &v.encap,
                    channel_id,
                    psk_length_in_bytes: v.psk_length_in_bytes,
                };
                let psk = self
                    .client
                    .aqc
                    .handler
                    .bidi_channel_received(&mut self.client.aqc.eng.clone(), &effect)
                    .map_err(AqcError::ChannelCreation)?;
                debug!("psk id: {:?}", psk.identity());
            }
            UniReceived(v) => {
                let encap = UniPeerEncap::<CS>::from_bytes(&v.encap)
                    .context("unable to get encap")
                    .map_err(AqcError::Encap)?;
                let channel_id: UniChannelId = encap.id();
                let effect = UniChannelReceived {
                    parent_cmd_id: v.parent_cmd_id,
                    author_id: v.author_id.into_id().into(),
                    author_enc_pk: &v.author_enc_pk,
                    send_id: v.send_id.into_id().into(),
                    recv_id: v.recv_id.into_id().into(),
                    peer_enc_key_id: v.peer_enc_key_id,
                    label_id: v.label_id.into_id().into(),
                    encap: &v.encap,
                    channel_id,
                    psk_length_in_bytes: v.psk_length_in_bytes,
                };
                let psk = self
                    .client
                    .aqc
                    .handler
                    .uni_channel_received(&mut self.client.aqc.eng.clone(), &effect)
                    .map_err(AqcError::ChannelCreation)?;
                debug!("psk id: {:?}", psk.identity());
            }
            _ => {}
        }

        Ok(())
    }

    /// Waits for a peer to create an AQC channel with this client.
    pub async fn receive_channel(&mut self) -> Option<AqcChannelType> {
        self.client.aqc.receive_channel().await
    }
}

// TODO: this was borrowed from daemon.rs. Move to util crate for reuse.
/// Loads a key from a file or generates and writes a new one.
async fn load_or_gen_key<K: SecretKey>(path: impl AsRef<Path>) -> anyhow::Result<K> {
    pub async fn load_or_gen_key_inner<K: SecretKey>(path: &Path) -> anyhow::Result<K> {
        match fs::read(&path).await {
            Ok(buf) => {
                tracing::info!("loading key");
                let key =
                    Import::import(buf.as_slice()).context("unable to import key from file")?;
                Ok(key)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                tracing::info!("generating key");
                let key = K::new(&mut Rng);
                let bytes = key
                    .try_export_secret()
                    .context("unable to export new key")?;
                aranya_util::write_file(&path, bytes.as_bytes())
                    .await
                    .context("unable to write key")?;
                Ok(key)
            }
            Err(err) => Err(err).context("unable to read key"),
        }
    }
    let path = path.as_ref();
    load_or_gen_key_inner(path)
        .instrument(tracing::info_span!("load_or_gen_key", ?path))
        .await
        .with_context(|| format!("load_or_gen_key({path:?})"))
}
