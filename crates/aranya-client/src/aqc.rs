//! AQC support.

use std::{io, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use aranya_aqc_util::{
    BidiChannelCreated, BidiChannelReceived, Handler, UniChannelCreated, UniChannelReceived,
};
use aranya_crypto::{
    aead::Aead, default::DefaultEngine, generic_array::GenericArray, import::Import,
    keys::SecretKeyBytes, keystore::fs_keystore::Store, CipherSuite, Random, Rng,
};
pub use aranya_daemon_api::AqcId;
use aranya_daemon_api::{
    AqcChannelInfo::*, AqcCtrl, DeviceId, KeyStoreInfo, NetIdentifier, TeamId, CS,
};
use aranya_fast_channels::{Label, NodeId};
use tarpc::context;
use tokio::fs;
use tracing::{debug, info, instrument};

use crate::error::AqcError;

// TODO: use same generics as daemon.
/// CE = Crypto Engine
pub(crate) type CE = DefaultEngine;
/// KS = Key Store
pub(crate) type KS = Store;

/// Length of a PSK key.
const PSK_KEY_LEN: u16 = 32;

/// Sends and receives AQC messages.
pub(crate) struct AqcChannelsImpl {
    // TODO: add Aqc fields.
    handler: Handler<Store>,
    eng: CE,
}

impl AqcChannelsImpl {
    /// Creates a new `FastChannelsImpl` listening for connections on `address`.
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
            let key = load_or_gen_key_wrap_key(keystore_info.wrapped_key).await?;
            CE::new(&key, Rng)
        };

        Ok(Self { handler, eng })
    }
}

/// Aranya Fast Channels client that allows for opening and closing channels and
/// sending data between peers.
pub struct AqcChannels<'a> {
    client: &'a mut crate::Client,
}

impl<'a> AqcChannels<'a> {
    pub(crate) fn new(client: &'a mut crate::Client) -> Self {
        Self { client }
    }

    /// Creates a bidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label))]
    pub async fn create_bidi_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label: Label,
    ) -> Result<(AqcId, AqcCtrl)> {
        debug!("creating bidi channel");

        let node_id: NodeId = 0.into();
        //let node_id = self.client.aqc.get_next_node_id().await?;
        debug!(%node_id, "selected node ID");

        let (aqc_id, aqc_ctrl, aqc_info) = self
            .client
            .daemon
            .create_aqc_bidi_channel(context::current(), team_id, peer.clone(), node_id, label)
            .await??;
        debug!(%aqc_id, %node_id, %label, "created bidi channel");

        if let BidiCreated(v) = aqc_info {
            let psk = self.client.aqc.handler.bidi_channel_created(
                &mut self.client.aqc.eng.clone(),
                &BidiChannelCreated {
                    parent_cmd_id: v.parent_cmd_id,
                    author_id: v.author_id.into_id().into(),
                    author_enc_key_id: v.author_enc_key_id,
                    peer_id: v.peer_id.into_id().into(),
                    peer_enc_pk: &v.peer_enc_pk,
                    label_id: v.label_id,
                    channel_id: v.channel_id,
                    psk_length_in_bytes: 32, // TODO: don't hard-code
                },
            )?;
            debug!("psk id: {:?}", psk.identity());

            // TODO: send ctrl msg via network.
        }

        // TODO: for testing only. Send ctrl via network instead of returning.
        Ok((aqc_id, aqc_ctrl))
    }

    /// Creates a unidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label))]
    pub async fn create_uni_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label: Label,
    ) -> Result<(AqcId, AqcCtrl)> {
        debug!("creating aqc uni channel");

        // TODO: use correct node ID.
        let node_id: NodeId = 0.into();
        debug!(%node_id, "selected node ID");

        let (aqc_id, aqc_ctrl, aqc_info) = self
            .client
            .daemon
            .create_aqc_uni_channel(context::current(), team_id, peer.clone(), node_id, label)
            .await??;
        debug!(%aqc_id, %node_id, %label, "created aqc uni channel");

        if let UniCreated(v) = aqc_info {
            let psk = self.client.aqc.handler.uni_channel_created(
                &mut self.client.aqc.eng.clone(),
                &UniChannelCreated {
                    parent_cmd_id: v.parent_cmd_id,
                    author_id: v.author_id.into_id().into(),
                    author_enc_key_id: v.author_enc_key_id,
                    send_id: v.send_id.into_id().into(),
                    recv_id: v.recv_id.into_id().into(),
                    peer_enc_pk: &v.peer_enc_pk,
                    label_id: v.label_id,
                    channel_id: v.channel_id,
                    psk_length_in_bytes: 32, // TODO: don't hard-code
                },
            )?;
            debug!("psk id: {:?}", psk.identity());

            // TODO: send ctrl msg via network.
        }

        // TODO: for testing only. Send ctrl via network instead of returning.
        Ok((aqc_id, aqc_ctrl))
    }

    /// Deletes an AQC channel.
    // TODO(eric): Is it an error if the channel does not exist?
    #[instrument(skip_all, fields(aqc_id = %id))]
    pub async fn delete_channel(&mut self, id: AqcId) -> crate::Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_aqc_channel(context::current(), id)
            .await??;
        //self.client.aqc.remove_channel(id).await;
        Ok(())
    }

    /// Receives an AQC ctrl message.
    // TODO: this method is pub for testing.
    // In final AQC implementation, it will only be invoked when a ctrl msg is received via the network.
    pub async fn receive_aqc_ctrl(&mut self, team: TeamId, ctrl: AqcCtrl) -> Result<()> {
        // TODO: use correct node ID
        let node_id: NodeId = 0.into();

        let (_aqc_id, _peer, aqc_info) = self
            .client
            .daemon
            .receive_aqc_ctrl(context::current(), team, node_id, ctrl)
            .await??;

        match aqc_info {
            BidiReceived(v) => {
                let psk = self.client.aqc.handler.bidi_channel_received(
                    &mut self.client.aqc.eng.clone(),
                    &BidiChannelReceived {
                        parent_cmd_id: v.parent_cmd_id,
                        author_id: v.author_id.into_id().into(),
                        author_enc_pk: &v.author_enc_pk,
                        peer_id: v.peer_id.into_id().into(),
                        peer_enc_key_id: v.peer_enc_key_id,
                        label_id: v.label_id,
                        encap: &v.encap,
                        channel_id: v.channel_id,
                        psk_length_in_bytes: PSK_KEY_LEN,
                    },
                )?;
                debug!("psk id: {:?}", psk.identity());
            }
            UniReceived(v) => {
                let psk = self.client.aqc.handler.uni_channel_received(
                    &mut self.client.aqc.eng.clone(),
                    &UniChannelReceived {
                        parent_cmd_id: v.parent_cmd_id,
                        author_id: v.author_id.into_id().into(),
                        author_enc_pk: &v.author_enc_pk,
                        send_id: v.send_id.into_id().into(),
                        recv_id: v.recv_id.into_id().into(),
                        peer_enc_key_id: v.peer_enc_key_id,
                        label_id: v.label_id,
                        encap: &v.encap,
                        channel_id: v.channel_id,
                        psk_length_in_bytes: PSK_KEY_LEN,
                    },
                )?;
                debug!("psk id: {:?}", psk.identity());
            }
            _ => {}
        }

        Ok(())
    }
}

// TODO: borrowed from daemon.
type KeyWrapKeyBytes = SecretKeyBytes<<<CS as CipherSuite>::Aead as Aead>::KeySize>;
type KeyWrapKey = <<CS as CipherSuite>::Aead as Aead>::Key;

// TODO: this was borrowed from daemon.rs. Move to util crate for reuse.
/// Loads the key wrapping key used by [`CryptoEngine`].
async fn load_or_gen_key_wrap_key(path: PathBuf) -> Result<KeyWrapKey> {
    let (bytes, loaded) = match fs::read(&path).await {
        Ok(buf) => {
            info!("loaded key wrap key");
            let bytes = KeyWrapKeyBytes::new(
                *GenericArray::try_from_slice(&buf)
                    .map_err(|_| anyhow!("invalid key wrap key length"))?,
            );
            (bytes, true)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            info!("generating key wrap key");
            let bytes = KeyWrapKeyBytes::random(&mut Rng);
            (bytes, false)
        }
        Err(err) => bail!("unable to read key wrap key: {err}"),
    };

    // Import before writing in case importing fails.
    let key = Import::import(bytes.as_bytes()).context("unable to import new key wrap key")?;
    if !loaded {
        aranya_util::write_file(&path, bytes.as_bytes())
            .await
            .context("unable to write key wrap key")?;
    }
    Ok(key)
}
