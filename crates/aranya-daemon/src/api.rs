//! Implementation of daemon's `tarpc` API.
//! Trait for API interface is defined in `crates/aranya-daemon-api`

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use core::{
    future::{self, Future},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use std::{collections::BTreeMap, io, path::PathBuf, sync::Arc};

use anyhow::{anyhow, Context as _, Result};
use aranya_crypto::{CipherSuite, Csprng, DeviceId, Rng};
use aranya_daemon_api::{self as api, crypto::LengthDelimitedCodec, DaemonApi, CS};
use aranya_fast_channels::{Label, NodeId};
use aranya_keygen::PublicKeys;
use aranya_runtime::GraphId;
use aranya_util::Addr;
use bimap::BiBTreeMap;
use buggy::BugExt;
use futures_util::{Stream, StreamExt, TryStreamExt};
use tarpc::{
    context,
    server::{self, Channel},
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{mpsc, Mutex},
};
use tracing::{debug, error, info, instrument, warn};

pub(crate) use crate::keys::{ApiKey, PublicApiKey};
use crate::{
    aranya::Actions,
    policy::{ChanOp, Effect, KeyBundle, Role},
    sync::SyncPeers,
    Client, EF,
};

#[cfg(feature = "afc")]
mod afc_imports {
    pub(super) use aranya_afc_util::Handler;
    pub(super) use aranya_crypto::keystore::fs_keystore::Store;
    pub(super) use aranya_fast_channels::shm::WriteState;

    pub(super) use crate::CE;
}
#[cfg(feature = "afc")]
#[allow(clippy::wildcard_imports)]
use afc_imports::*;

async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(fut);
}

/// returns first effect matching a particular type.
/// returns None if there are no matching effects.
#[macro_export]
macro_rules! find_effect {
    ($effects:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {
        $effects.into_iter().find(|e| matches!(e, $pattern $(if $guard)?))
    }
}

type EffectReceiver = mpsc::Receiver<(GraphId, Vec<EF>)>;

/// Daemon API Server.
pub struct DaemonApiServer {
    // Used to encrypt data sent over the API.
    sk: ApiKey<CS>,
    daemon_sock: PathBuf,
    /// Channel for receiving effects from the syncer.
    recv_effects: EffectReceiver,
    // TODO(eric): make this Arc<DaemonApiHandler>?
    handler: DaemonApiHandler,
}

impl DaemonApiServer {
    /// Create new `DaemonApiServer`.
    #[instrument(skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<Client>,
        local_addr: SocketAddr,
        keystore_info: api::KeyStoreInfo,
        daemon_sock: PathBuf,
        sk: ApiKey<CS>,
        pk: Arc<PublicKeys<CS>>,
        peers: SyncPeers,
        recv_effects: EffectReceiver,
    ) -> Self {
        Self {
            daemon_sock,
            sk,
            recv_effects,
            handler: DaemonApiHandler {
                client,
                local_addr,
                pk,
                peers,
                keystore_info,
                aqc_peers: PeerMap::default(),
            },
        }
    }

    /// Run the RPC server.
    #[instrument(skip_all)]
    #[allow(clippy::disallowed_macros)]
    pub async fn serve(mut self) -> Result<()> {
        let listener = UnixListener::bind(&self.daemon_sock)?;
        info!(
            addr = ?listener
                .local_addr()
                .assume("should be able to retrieve local addr")?
                .as_pathname()
                .assume("addr should be a pathname")?,
            "listening"
        );

        let info = self.daemon_sock.as_os_str().as_encoded_bytes();
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(usize::MAX)
            .new_codec();
        let server = api::crypto::server::<
            _,
            <CS as CipherSuite>::Kem,
            <CS as CipherSuite>::Kdf,
            <CS as CipherSuite>::Aead,
            _,
            _,
        >(
            UnixListenerStream(listener),
            codec,
            self.sk.into_inner(),
            info,
        );

        // TODO: determine if there's a performance benefit to putting these branches in different threads.
        tokio::join!(
            server
                .inspect_err(|err| warn!(%err, "accept error"))
                // Ignore accept errors.
                .filter_map(|r| future::ready(r.ok()))
                .map(server::BaseChannel::with_defaults)
                .map(|channel| {
                    debug!("accepted channel connection");
                    channel
                        .execute(self.handler.clone().serve())
                        .for_each(spawn)
                })
                .buffer_unordered(10)
                .for_each(|_| async {}),
            async {
                while let Some((graph, effects)) = self.recv_effects.recv().await {
                    if let Err(e) = self.handler.handle_effects(graph, &effects, None).await {
                        error!(?e, "error handling effects");
                    }
                }
            },
        );
        Ok(())
    }
}

#[derive(Debug)]
struct UnixListenerStream(UnixListener);
impl Stream for UnixListenerStream {
    type Item = io::Result<UnixStream>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<UnixStream>>> {
        match self.0.poll_accept(cx) {
            Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A mapping of `Net ID <=> Device ID`, separated by `Graph ID`.
type PeerMap = Arc<Mutex<BTreeMap<GraphId, BiBTreeMap<api::NetIdentifier, DeviceId>>>>;

#[derive(Clone)]
struct DaemonApiHandler {
    /// Aranya client for
    client: Arc<Client>,
    /// Local socket address of the API.
    local_addr: SocketAddr,
    /// Public keys of current device.
    pk: Arc<PublicKeys<CS>>,
    /// Aranya sync peers,
    peers: SyncPeers,
    /// Key store paths.
    keystore_info: api::KeyStoreInfo,

    /// AQC peers.
    aqc_peers: PeerMap,
}

impl DaemonApiHandler {
    fn get_pk(&self) -> api::Result<KeyBundle> {
        Ok(KeyBundle::try_from(&*self.pk).context("bad key bundle")?)
    }

    /// Handles effects resulting from invoking an Aranya action.
    #[instrument(skip_all)]
    #[allow(unused_variables)]
    async fn handle_effects(
        &self,
        graph: GraphId,
        effects: &[Effect],
        node_id: Option<NodeId>,
    ) -> Result<()> {
        for effect in effects {
            debug!(?effect, "handling effect");
            match effect {
                Effect::TeamCreated(_team_created) => {}
                Effect::TeamTerminated(_team_terminated) => {}
                Effect::MemberAdded(_member_added) => {}
                Effect::MemberRemoved(_member_removed) => {}
                Effect::OwnerAssigned(_owner_assigned) => {}
                Effect::AdminAssigned(_admin_assigned) => {}
                Effect::OperatorAssigned(_operator_assigned) => {}
                Effect::OwnerRevoked(_owner_revoked) => {}
                Effect::AdminRevoked(_admin_revoked) => {}
                Effect::OperatorRevoked(_operator_revoked) => {}
                #[cfg(any())]
                Effect::AfcNetworkNameSet(e) => {
                    self.afc_peers
                        .lock()
                        .await
                        .entry(graph)
                        .or_default()
                        .insert(
                            api::NetIdentifier(e.net_identifier.clone()),
                            e.device_id.into(),
                        );
                }
                Effect::LabelCreated(_) => {}
                Effect::LabelDeleted(_) => {}
                Effect::LabelAssigned(_) => {}
                Effect::LabelRevoked(_) => {}
                Effect::AqcNetworkNameSet(e) => {
                    self.aqc_peers
                        .lock()
                        .await
                        .entry(graph)
                        .or_default()
                        .insert(
                            api::NetIdentifier(e.net_identifier.clone()),
                            e.device_id.into(),
                        );
                }
                Effect::AqcNetworkNameUnset(_network_name_unset) => {}
                Effect::QueriedLabel(_) => {}
                #[cfg(any())]
                Effect::AfcBidiChannelCreated(v) => {
                    debug!("received AfcBidiChannelCreated effect");
                    if let Some(node_id) = node_id {
                        self.afc_bidi_channel_created(v, node_id).await?
                    }
                }
                #[cfg(any())]
                Effect::AfcBidiChannelReceived(v) => {
                    debug!("received AfcBidiChannelReceived effect");
                    if let Some(node_id) = node_id {
                        self.afc_bidi_channel_received(v, node_id).await?
                    }
                }
                Effect::AqcBidiChannelCreated(_) => {}
                Effect::AqcBidiChannelReceived(_) => {}
                Effect::AqcUniChannelCreated(_) => {}
                Effect::AqcUniChannelReceived(_) => {}
                Effect::QueryDevicesOnTeamResult(_) => {}
                Effect::QueryDeviceRoleResult(_) => {}
                Effect::QueryDeviceKeyBundleResult(_) => {}
                Effect::QueryAqcNetIdentifierResult(_) => {}
                Effect::QueriedLabelAssignment(_) => {}
                Effect::QueryLabelExistsResult(_) => {}
            }
        }
        Ok(())
    }

    /// Reacts to a bidirectional AFC channel being created.
    #[instrument(skip(self), fields(effect = ?v))]
    #[cfg(any())]
    async fn afc_bidi_channel_created(
        &self,
        v: &AfcBidiChannelCreatedEffect,
        node_id: NodeId,
    ) -> Result<()> {
        debug!("received BidiChannelCreated effect");
        // NB: this shouldn't happen because the policy should
        // ensure that label fits inside a `u32`.
        let label = Label::new(u32::try_from(v.label).assume("`label` is out of range")?);
        // TODO: don't clone the eng.
        let AfcBidiKeys { seal, open } = self.afc_handler.lock().await.bidi_channel_created(
            &mut self.eng.clone(),
            &AfcBidiChannelCreated {
                parent_cmd_id: v.parent_cmd_id,
                author_id: v.author_id.into(),
                author_enc_key_id: v.author_enc_key_id.into(),
                peer_id: v.peer_id.into(),
                peer_enc_pk: &v.peer_enc_pk,
                label,
                key_id: v.channel_key_id.into(),
            },
        )?;
        let label = Label::new(v.label.try_into().expect("expected label conversion"));
        let channel_id = ChannelId::new(node_id, label);
        debug!(%channel_id, "created AFC bidi channel `ChannelId`");
        self.afc
            .lock()
            .await
            .add(channel_id, Directed::Bidirectional { seal, open })
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;
        Ok(())
    }

    /// Reacts to a bidirectional AFC channel being created.
    #[instrument(skip_all)]
    #[cfg(any())]
    async fn afc_bidi_channel_received(
        &self,
        v: &AfcBidiChannelReceivedEffect,
        node_id: NodeId,
    ) -> Result<()> {
        // NB: this shouldn't happen because the policy should
        // ensure that label fits inside a `u32`.
        let label = Label::new(u32::try_from(v.label).assume("`label` is out of range")?);
        let AfcBidiKeys { seal, open } = self.afc_handler.lock().await.bidi_channel_received(
            &mut self.eng.clone(),
            &AfcBidiChannelReceived {
                parent_cmd_id: v.parent_cmd_id,
                author_id: v.author_id.into(),
                author_enc_pk: &v.author_enc_pk,
                peer_id: v.peer_id.into(),
                peer_enc_key_id: v.peer_enc_key_id.into(),
                label,
                encap: &v.encap,
            },
        )?;
        let label = Label::new(v.label.try_into().expect("expected label conversion"));
        let channel_id = ChannelId::new(node_id, label);
        debug!(?channel_id, "received AFC bidi channel `ChannelId`");
        self.afc
            .lock()
            .await
            .add(channel_id, Directed::Bidirectional { seal, open })
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;
        Ok(())
    }
}

impl DaemonApi for DaemonApiHandler {
    #[instrument(skip(self))]
    async fn hello(self, context: context::Context) -> api::Result<u32> {
        Ok(42)
    }

    #[instrument(skip(self))]
    async fn get_keystore_info(self, context: context::Context) -> api::Result<api::KeyStoreInfo> {
        Ok(self.keystore_info)
    }

    #[instrument(skip(self))]
    async fn aranya_local_addr(self, context: context::Context) -> api::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    #[instrument(skip(self))]
    async fn get_key_bundle(self, _: context::Context) -> api::Result<api::KeyBundle> {
        Ok(self
            .get_pk()
            .context("unable to get device public keys")?
            .into())
    }

    #[instrument(skip(self))]
    async fn get_device_id(self, _: context::Context) -> api::Result<api::DeviceId> {
        Ok(self
            .pk
            .ident_pk
            .id()
            .context("unable to get device ID")?
            .into_id()
            .into())
    }

    #[instrument(skip(self))]
    async fn add_sync_peer(
        mut self,
        _: context::Context,
        peer: Addr,
        team: api::TeamId,
        cfg: api::SyncPeerConfig,
    ) -> api::Result<()> {
        self.peers
            .add_peer(peer, team.into_id().into(), cfg)
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn sync_now(
        self,
        _: context::Context,
        peer: Addr,
        team: api::TeamId,
        cfg: Option<api::SyncPeerConfig>,
    ) -> api::Result<()> {
        self.peers
            .sync_now(peer, team.into_id().into(), cfg)
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_sync_peer(
        mut self,
        _: context::Context,
        peer: Addr,
        team: api::TeamId,
    ) -> api::Result<()> {
        self.peers
            .remove_peer(peer, team.into_id().into())
            .await
            .context("unable to remove sync peer")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn add_team(self, _: context::Context, team: api::TeamId) -> api::Result<()> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn remove_team(self, _: context::Context, team: api::TeamId) -> api::Result<()> {
        todo!();
    }

    #[instrument(skip(self))]
    async fn create_team(self, _: context::Context) -> api::Result<api::TeamId> {
        info!("create_team");
        let nonce = &mut [0u8; 16];
        Rng.fill_bytes(nonce);
        let pk = self.get_pk()?;
        let (graph_id, _) = self
            .client
            .create_team(pk, Some(nonce))
            .await
            .context("unable to create team")?;
        debug!(?graph_id);
        Ok(graph_id.into_id().into())
    }

    #[instrument(skip(self))]
    async fn close_team(self, _: context::Context, team: api::TeamId) -> api::Result<()> {
        todo!();
    }

    #[instrument(skip(self))]
    async fn add_device_to_team(
        self,
        _: context::Context,
        team: api::TeamId,
        keys: api::KeyBundle,
    ) -> api::Result<()> {
        self.client
            .actions(&team.into_id().into())
            .add_member(keys.into())
            .await
            .context("unable to add device to team")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_device_from_team(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<()> {
        self.client
            .actions(&team.into_id().into())
            .remove_member(device.into_id().into())
            .await
            .context("unable to remove device from team")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn assign_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        role: api::Role,
    ) -> api::Result<()> {
        self.client
            .actions(&team.into_id().into())
            .assign_role(device.into_id().into(), role.into())
            .await
            .context("unable to assign role")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn revoke_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        role: api::Role,
    ) -> api::Result<()> {
        self.client
            .actions(&team.into_id().into())
            .revoke_role(device.into_id().into(), role.into())
            .await
            .context("unable to revoke device role")?;
        Ok(())
    }

    #[cfg(any())]
    #[instrument(skip(self))]
    async fn assign_afc_net_identifier(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        name: api::NetIdentifier,
    ) -> api::Result<()> {
        let effects = self
            .client
            .actions(&team.into_id().into())
            .set_afc_network_name(device.into_id().into(), name.0)
            .await
            .context("unable to assign afc network identifier")?;
        self.handle_effects(&effects, None).await?;
        Ok(())
    }

    #[cfg(any())]
    #[instrument(skip(self))]
    async fn remove_afc_net_identifier(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        name: api::NetIdentifier,
    ) -> api::Result<()> {
        self.client
            .actions(&team.into_id().into())
            .unset_afc_network_name(device.into_id().into())
            .await
            .context("unable to remove afc network identifier")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn assign_aqc_net_identifier(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        name: api::NetIdentifier,
    ) -> api::Result<()> {
        let effects = self
            .client
            .actions(&team.into_id().into())
            .set_aqc_network_name(device.into_id().into(), name.0)
            .await
            .context("unable to assign aqc network identifier")?;
        self.handle_effects(GraphId::from(team.into_id()), &effects, None)
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_aqc_net_identifier(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        name: api::NetIdentifier,
    ) -> api::Result<()> {
        self.client
            .actions(&team.into_id().into())
            .unset_aqc_network_name(device.into_id().into())
            .await
            .context("unable to remove aqc net identifier")?;
        Ok(())
    }

    #[cfg(any())]
    #[instrument(skip(self))]
    async fn create_afc_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label: Label,
    ) -> api::Result<()> {
        self.client
            .actions(&team.into_id().into())
            .define_afc_label(label)
            .await
            .context("unable to create label")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn create_afc_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label: Label,
    ) -> api::Result<()> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    #[cfg(any())]
    #[instrument(skip(self))]
    async fn delete_afc_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label: Label,
    ) -> api::Result<()> {
        self.client
            .actions(&team.into_id().into())
            .undefine_afc_label(label)
            .await
            .context("unable to delete label")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_afc_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label: Label,
    ) -> api::Result<()> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    #[cfg(any())]
    #[instrument(skip(self))]
    async fn assign_afc_label(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label: Label,
    ) -> api::Result<()> {
        // TODO: support other channel permissions.
        self.client
            .actions(&team.into_id().into())
            .assign_afc_label(device.into_id().into(), label, ChanOp::SendRecv)
            .await
            .context("unable to assign label")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn assign_afc_label(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label: Label,
    ) -> api::Result<()> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    #[cfg(any())]
    #[instrument(skip(self))]
    async fn revoke_afc_label(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label: Label,
    ) -> api::Result<()> {
        let id = self.pk.ident_pk.id()?;
        self.client
            .actions(&team.into_id().into())
            .revoke_afc_label(id, label)
            .await
            .context("unable to revoke label")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn revoke_afc_label(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label: Label,
    ) -> api::Result<()> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    #[cfg(any())]
    #[instrument(skip_all)]
    async fn create_afc_bidi_channel(
        self,
        _: context::Context,
        team: api::TeamId,
        peer: api::NetIdentifier,
        node_id: NodeId,
        label: Label,
    ) -> api::Result<(AfcId, AfcCtrl)> {
        info!("create_afc_bidi_channel");

        let graph = GraphId::from(team.into_id());

        let peer_id = self
            .afc_peers
            .lock()
            .await
            .get(&graph)
            .and_then(|map| map.get_by_left(&peer))
            .copied()
            .context("unable to lookup peer")?;

        let (ctrl, effects) = self
            .client
            .actions(&graph)
            .create_afc_bidi_channel_off_graph(peer_id, label)
            .await?;
        let id = self.pk.ident_pk.id()?;

        let Some(Effect::AfcBidiChannelCreated(e)) =
            find_effect!(&effects, Effect::AfcBidiChannelCreated(e) if e.author_id == id.into())
        else {
            return Err(anyhow::anyhow!("unable to find AfcBidiChannelCreated effect").into());
        };
        let afc_id: AfcId = e.channel_key_id.into();
        debug!(?afc_id, "processed afc ID");

        self.handle_effects(&effects, Some(node_id)).await?;
        Ok((afc_id, ctrl))
    }

    #[instrument(skip_all)]
    async fn create_afc_bidi_channel(
        self,
        _: context::Context,
        _: api::TeamId,
        _: api::NetIdentifier,
        _: NodeId,
        _: Label,
    ) -> api::Result<(api::AfcId, api::AfcCtrl)> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    #[cfg(any())]
    #[instrument(skip(self))]
    async fn delete_afc_channel(self, _: context::Context, chan: AfcId) -> api::Result<AfcCtrl> {
        // TODO: remove AFC channel from Aranya.
        todo!();
    }

    #[instrument(skip(self))]
    async fn delete_afc_channel(
        self,
        _: context::Context,
        _: api::AfcId,
    ) -> api::Result<api::AfcCtrl> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    #[cfg(any())]
    #[instrument(skip_all)]
    async fn receive_afc_ctrl(
        self,
        _: context::Context,
        team: api::TeamId,
        node_id: api::NodeId,
        ctrl: api::AfcCtrl,
    ) -> api::Result<(AfcId, NetIdentifier, Label)> {
        let graph = GraphId::from(team.into_id());
        let mut session = self.client.session_new(&graph).await?;
        for cmd in ctrl {
            let effects = self.client.session_receive(&mut session, &cmd).await?;
            let id = self.pk.ident_pk.id()?;
            self.handle_effects(&effects, Some(node_id)).await?;
            let Some(Effect::AfcBidiChannelReceived(e)) =
                find_effect!(&effects, Effect::AfcBidiChannelReceived(e) if e.peer_id == id.into())
            else {
                continue;
            };
            let encap =
                BidiPeerEncap::<api::CS>::from_bytes(&e.encap).context("unable to get encap")?;
            let afc_id: AfcId = encap.id().into();
            debug!(?afc_id, "processed afc ID");
            let label = Label::new(e.label.try_into().expect("expected label conversion"));
            let net = self
                .afc_peers
                .lock()
                .await
                .get(&graph)
                .and_then(|map| map.get_by_right(&e.author_id.into()))
                .context("missing net identifier for channel author")?
                .clone();
            return Ok((afc_id, net, label));
        }
        Err(anyhow!("unable to find AfcBidiChannelReceived effect").into())
    }

    async fn receive_afc_ctrl(
        self,
        _: context::Context,
        _: api::TeamId,
        _: NodeId,
        _: api::AfcCtrl,
    ) -> api::Result<(api::AfcId, api::NetIdentifier, Label)> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    #[instrument(skip_all)]
    async fn create_aqc_bidi_channel(
        self,
        _: context::Context,
        team: api::TeamId,
        peer: api::NetIdentifier,
        label: api::LabelId,
    ) -> api::Result<(api::AqcCtrl, api::AqcBidiChannelCreatedInfo)> {
        info!("create_aqc_bidi_channel");

        let graph = GraphId::from(team.into_id());

        let peer_id = self
            .aqc_peers
            .lock()
            .await
            .get(&graph)
            .and_then(|map| map.get_by_left(&peer))
            .copied()
            .context("unable to lookup peer")?;

        let (ctrl, effects) = self
            .client
            .actions(&graph)
            .create_aqc_bidi_channel_off_graph(peer_id, label.into_id().into())
            .await?;
        let id = self.pk.ident_pk.id()?;

        let Some(Effect::AqcBidiChannelCreated(e)) =
            find_effect!(&effects, Effect::AqcBidiChannelCreated(e) if e.author_id == id.into())
        else {
            return Err(anyhow::anyhow!("unable to find AqcBidiChannelCreated effect").into());
        };

        self.handle_effects(graph, &effects, None).await?;

        let info = api::AqcBidiChannelCreatedInfo {
            parent_cmd_id: e.parent_cmd_id,
            author_id: e.author_id.into(),
            author_enc_key_id: e.author_enc_key_id.into(),
            peer_id: e.peer_id.into(),
            peer_enc_pk: e.peer_enc_pk.clone(),
            label_id: e.label_id.into(),
            channel_id: e.channel_id.into(),
            author_secrets_id: e.author_secrets_id.into(),
            psk_length_in_bytes: u16::try_from(e.psk_length_in_bytes)
                .assume("`psk_length_in_bytes` is out of range")
                .context("psk_length_in_bytes is out of range")?,
        };

        Ok((ctrl, info))
    }

    #[instrument(skip_all)]
    async fn create_aqc_uni_channel(
        self,
        _: context::Context,
        team: api::TeamId,
        peer: api::NetIdentifier,
        label: api::LabelId,
    ) -> api::Result<(api::AqcCtrl, api::AqcUniChannelCreatedInfo)> {
        info!("create_aqc_uni_channel");

        let graph = GraphId::from(team.into_id());

        let peer_id = self
            .aqc_peers
            .lock()
            .await
            .get(&graph)
            .and_then(|map| map.get_by_left(&peer))
            .copied()
            .context("unable to lookup peer")?;

        let id = self.pk.ident_pk.id()?;
        let (ctrl, effects) = self
            .client
            .actions(&graph)
            .create_aqc_uni_channel_off_graph(id, peer_id, label.into_id().into())
            .await?;

        let Some(Effect::AqcUniChannelCreated(e)) =
            find_effect!(&effects, Effect::AqcUniChannelCreated(e) if e.author_id == id.into())
        else {
            return Err(anyhow::anyhow!("unable to find AqcUniChannelCreated effect").into());
        };

        self.handle_effects(graph, &effects, None).await?;

        let info = api::AqcUniChannelCreatedInfo {
            parent_cmd_id: e.parent_cmd_id,
            author_id: e.author_id.into(),
            author_enc_key_id: e.author_enc_key_id.into(),
            send_id: e.sender_id.into(),
            recv_id: e.receiver_id.into(),
            peer_enc_pk: e.peer_enc_pk.clone(),
            label_id: e.label_id.into(),
            channel_id: e.channel_id.into(),
            author_secrets_id: e.author_secrets_id.into(),
            psk_length_in_bytes: u16::try_from(e.psk_length_in_bytes)
                .assume("`psk_length_in_bytes` is out of range")
                .context("psk_length_in_bytes is out of range")?,
        };

        Ok((ctrl, info))
    }

    #[instrument(skip(self))]
    async fn delete_aqc_bidi_channel(
        self,
        _: context::Context,
        chan: api::AqcBidiChannelId,
    ) -> api::Result<api::AqcCtrl> {
        // TODO: remove AQC bidi channel from Aranya.
        todo!();
    }

    #[instrument(skip(self))]
    async fn delete_aqc_uni_channel(
        self,
        _: context::Context,
        chan: api::AqcUniChannelId,
    ) -> api::Result<api::AqcCtrl> {
        // TODO: remove AQC uni channel from Aranya.
        todo!();
    }

    #[instrument(skip_all)]
    async fn receive_aqc_ctrl(
        self,
        _: context::Context,
        team: api::TeamId,
        ctrl: api::AqcCtrl,
    ) -> api::Result<(api::NetIdentifier, api::AqcChannelInfo)> {
        let graph = GraphId::from(team.into_id());
        let mut session = self.client.session_new(&graph).await?;
        for cmd in ctrl {
            let effects = self.client.session_receive(&mut session, &cmd).await?;
            let id = self.pk.ident_pk.id()?;
            self.handle_effects(graph, &effects, None).await?;
            if let Some(Effect::AqcBidiChannelReceived(e)) =
                find_effect!(&effects, Effect::AqcBidiChannelReceived(e) if e.peer_id == id.into())
            {
                let aqc_info = api::AqcChannelInfo::BidiReceived(api::AqcBidiChannelReceivedInfo {
                    parent_cmd_id: e.parent_cmd_id,
                    author_id: e.author_id.into(),
                    author_enc_pk: e.author_enc_pk.clone(),
                    peer_id: e.peer_id.into(),
                    peer_enc_key_id: e.peer_enc_key_id.into(),
                    label_id: e.label_id.into(),
                    encap: e.encap.clone(),
                    psk_length_in_bytes: u16::try_from(e.psk_length_in_bytes)
                        .assume("`psk_length_in_bytes` is out of range")?,
                });

                let net = self
                    .aqc_peers
                    .lock()
                    .await
                    .get(&graph)
                    .and_then(|map| map.get_by_right(&e.author_id.into()))
                    .context("missing net identifier for channel author")?
                    .clone();
                return Ok((net, aqc_info));
            };

            if let Some(Effect::AqcUniChannelReceived(e)) = find_effect!(&effects, Effect::AqcUniChannelReceived(e) if (e.sender_id == id.into() || e.receiver_id == id.into()))
            {
                let aqc_info = api::AqcChannelInfo::UniReceived(api::AqcUniChannelReceivedInfo {
                    parent_cmd_id: e.parent_cmd_id,
                    send_id: e.sender_id.into(),
                    recv_id: e.receiver_id.into(),
                    author_id: e.author_id.into(),
                    author_enc_pk: e.author_enc_pk.clone(),
                    peer_enc_key_id: e.peer_enc_key_id.into(),
                    label_id: e.label_id.into(),
                    encap: e.encap.clone(),
                    psk_length_in_bytes: u16::try_from(e.psk_length_in_bytes)
                        .assume("`psk_length_in_bytes` is out of range")?,
                });
                let net = self
                    .aqc_peers
                    .lock()
                    .await
                    .get(&graph)
                    .and_then(|map| map.get_by_right(&e.author_id.into()))
                    .context("missing net identifier for channel author")?
                    .clone();
                return Ok((net, aqc_info));
            };
        }
        Err(anyhow!("unable to find AqcBidiChannelReceived effect").into())
    }

    async fn assign_afc_net_identifier(
        self,
        _: context::Context,
        _: api::TeamId,
        _: api::DeviceId,
        _: api::NetIdentifier,
    ) -> api::Result<()> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    async fn remove_afc_net_identifier(
        self,
        _: context::Context,
        _: api::TeamId,
        _: api::DeviceId,
        _: api::NetIdentifier,
    ) -> api::Result<()> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    /// Create a label.
    async fn create_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label_name: String,
    ) -> api::Result<api::LabelId> {
        let effects = self
            .client
            .actions(&team.into_id().into())
            .create_label(label_name)
            .await
            .context("unable to create AQC label")?;
        if let Some(Effect::LabelCreated(e)) = find_effect!(&effects, Effect::LabelCreated(_e)) {
            Ok(e.label_id.into())
        } else {
            Err(anyhow!("unable to create AQC label").into())
        }
    }

    /// Delete a label.
    async fn delete_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label_id: api::LabelId,
    ) -> api::Result<()> {
        let effects = self
            .client
            .actions(&team.into_id().into())
            .delete_label(label_id.into_id().into())
            .await
            .context("unable to delete AQC label")?;
        if let Some(Effect::LabelDeleted(_e)) = find_effect!(&effects, Effect::LabelDeleted(_e)) {
            Ok(())
        } else {
            Err(anyhow!("unable to delete AQC label").into())
        }
    }

    /// Assign a label.
    async fn assign_label(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label_id: api::LabelId,
        op: api::ChanOp,
    ) -> api::Result<()> {
        let effects = self
            .client
            .actions(&team.into_id().into())
            .assign_label(
                device.into_id().into(),
                label_id.into_id().into(),
                op.into(),
            )
            .await
            .context("unable to assign AQC label")?;
        if let Some(Effect::LabelAssigned(_e)) = find_effect!(&effects, Effect::LabelAssigned(_e)) {
            Ok(())
        } else {
            Err(anyhow!("unable to assign AQC label").into())
        }
    }

    /// Revoke a label.
    async fn revoke_label(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label_id: api::LabelId,
    ) -> api::Result<()> {
        let effects = self
            .client
            .actions(&team.into_id().into())
            .revoke_label(device.into_id().into(), label_id.into_id().into())
            .await
            .context("unable to revoke AQC label")?;
        if let Some(Effect::LabelRevoked(_e)) = find_effect!(&effects, Effect::LabelRevoked(_e)) {
            Ok(())
        } else {
            Err(anyhow!("unable to revoke AQC label").into())
        }
    }

    /// Query devices on team.
    #[instrument(skip(self))]
    async fn query_devices_on_team(
        self,
        _: context::Context,
        team: api::TeamId,
    ) -> api::Result<Vec<api::DeviceId>> {
        let (_ctrl, effects) = self
            .client
            .actions(&team.into_id().into())
            .query_devices_on_team_off_graph()
            .await
            .context("unable to query devices on team")?;
        let mut devices: Vec<api::DeviceId> = Vec::new();
        for e in effects {
            if let Effect::QueryDevicesOnTeamResult(e) = e {
                devices.push(e.device_id.into());
            }
        }
        return Ok(devices);
    }
    /// Query device role.
    #[instrument(skip(self))]
    async fn query_device_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<api::Role> {
        let (_ctrl, effects) = self
            .client
            .actions(&team.into_id().into())
            .query_device_role_off_graph(device.into_id().into())
            .await
            .context("unable to query device role")?;
        if let Some(Effect::QueryDeviceRoleResult(e)) =
            find_effect!(&effects, Effect::QueryDeviceRoleResult(_e))
        {
            Ok(api::Role::from(e.role))
        } else {
            Err(anyhow!("unable to query device role").into())
        }
    }
    /// Query device keybundle.
    #[instrument(skip(self))]
    async fn query_device_keybundle(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<api::KeyBundle> {
        let (_ctrl, effects) = self
            .client
            .actions(&team.into_id().into())
            .query_device_keybundle_off_graph(device.into_id().into())
            .await
            .context("unable to query device keybundle")?;
        if let Some(Effect::QueryDeviceKeyBundleResult(e)) =
            find_effect!(effects, Effect::QueryDeviceKeyBundleResult(_e))
        {
            Ok(api::KeyBundle::from(e.device_keys))
        } else {
            Err(anyhow!("unable to query device keybundle").into())
        }
    }

    /// Query device label assignments.
    #[instrument(skip(self))]
    async fn query_device_label_assignments(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<Vec<api::Label>> {
        let (_ctrl, effects) = self
            .client
            .actions(&team.into_id().into())
            .query_label_assignments_off_graph(device.into_id().into())
            .await
            .context("unable to query device label assignments")?;
        let mut labels: Vec<api::Label> = Vec::new();
        for e in effects {
            if let Effect::QueriedLabelAssignment(e) = e {
                debug!("found label: {}", e.label_id);
                labels.push(api::Label {
                    id: e.label_id.into(),
                    name: e.label_name,
                });
            }
        }
        return Ok(labels);
    }

    #[cfg(any())]
    /// Query device AFC label assignments.
    #[instrument(skip(self))]
    async fn query_device_afc_label_assignments(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<Vec<Label>> {
        let (_ctrl, effects) = self
            .client
            .actions(&team.into_id().into())
            .query_device_afc_label_assignments_off_graph(device.into_id().into())
            .await
            .context("unable to query device label assignments")?;
        let mut labels = Vec::new();
        for e in effects {
            if let Effect::QueryDeviceAfcLabelAssignmentsResult(e) = e {
                let label = Label::new(
                    u32::try_from(e.label)
                        .assume("`label` is out of range")
                        .context("label is out of range")?,
                );
                debug!("found label: {} assigned to device: {}", label, device);
                labels.push(label);
            }
        }
        return Ok(labels);
    }

    /// Query device AFC label assignments.
    #[instrument(skip(self))]
    async fn query_device_afc_label_assignments(
        self,
        _: context::Context,
        _: api::TeamId,
        _: api::DeviceId,
    ) -> api::Result<Vec<Label>> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    /// Query AFC network ID.
    #[cfg(any())]
    #[instrument(skip(self))]
    async fn query_afc_net_identifier(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<Option<api::NetIdentifier>> {
        if let Ok((_ctrl, effects)) = self
            .client
            .actions(&team.into_id().into())
            .query_afc_net_identifier_off_graph(device.into_id().into())
            .await
        {
            if let Some(Effect::QueryAfcNetIdentifierResult(e)) =
                find_effect!(effects, Effect::QueryAfcNetIdentifierResult(_e))
            {
                return Ok(Some(api::NetIdentifier(e.net_identifier)));
            }
        }
        Ok(None)
    }

    /// Query AFC network ID.
    #[instrument(skip(self))]
    async fn query_afc_net_identifier(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<Option<api::NetIdentifier>> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    /// Query AQC network ID.
    #[instrument(skip(self))]
    async fn query_aqc_net_identifier(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<Option<api::NetIdentifier>> {
        if let Ok((_ctrl, effects)) = self
            .client
            .actions(&team.into_id().into())
            .query_aqc_net_identifier_off_graph(device.into_id().into())
            .await
        {
            if let Some(Effect::QueryAqcNetIdentifierResult(e)) =
                find_effect!(effects, Effect::QueryAqcNetIdentifierResult(_e))
            {
                return Ok(Some(api::NetIdentifier(e.net_identifier)));
            }
        }
        Ok(None)
    }

    /// Query label exists.
    async fn query_label_exists(
        self,
        _: context::Context,
        team: api::TeamId,
        label_id: api::LabelId,
    ) -> api::Result<bool> {
        let (_ctrl, effects) = self
            .client
            .actions(&team.into_id().into())
            .query_label_exists_off_graph(label_id.into_id().into())
            .await
            .context("unable to query label")?;
        if let Some(Effect::QueryLabelExistsResult(_e)) =
            find_effect!(&effects, Effect::QueryLabelExistsResult(_e))
        {
            Ok(true)
        } else {
            Err(anyhow!("unable to query whether label exists").into())
        }
    }

    /// Query AFC label exists.
    #[cfg(any())]
    #[instrument(skip(self))]
    async fn query_afc_label_exists(
        self,
        _: context::Context,
        team: api::TeamId,
        label: Label,
    ) -> api::Result<bool> {
        let (_ctrl, effects) = self
            .client
            .actions(&team.into_id().into())
            .query_afc_label_exists_off_graph(label)
            .await
            .context("unable to query label")?;
        if let Some(Effect::QueryLabelExistsResult(e)) =
            find_effect!(&effects, Effect::QueryLabelExistsResult(_e))
        {
            Ok(e.label_exists)
        } else {
            Err(anyhow!("unable to query whether afc label exists").into())
        }
    }

    /// Query AFC label exists.
    #[instrument(skip(self))]
    async fn query_afc_label_exists(
        self,
        _: context::Context,
        _: api::TeamId,
        _: Label,
    ) -> api::Result<bool> {
        Err(anyhow!("Aranya Fast Channels is disabled for this daemon!").into())
    }

    /// Query list of labels.
    async fn query_labels(
        self,
        _: context::Context,
        team: api::TeamId,
    ) -> api::Result<Vec<api::Label>> {
        let (_ctrl, effects) = self
            .client
            .actions(&team.into_id().into())
            .query_labels_off_graph()
            .await
            .context("unable to query labels")?;
        let mut labels: Vec<api::Label> = Vec::new();
        for e in effects {
            if let Effect::QueriedLabel(e) = e {
                debug!("found label: {}", e.label_id);
                labels.push(api::Label {
                    id: e.label_id.into(),
                    name: e.label_name,
                });
            }
        }
        Ok(labels)
    }
}

impl From<api::KeyBundle> for KeyBundle {
    fn from(value: api::KeyBundle) -> Self {
        KeyBundle {
            ident_key: value.identity,
            sign_key: value.signing,
            enc_key: value.encoding,
        }
    }
}

impl From<KeyBundle> for api::KeyBundle {
    fn from(value: KeyBundle) -> Self {
        api::KeyBundle {
            identity: value.ident_key,
            signing: value.sign_key,
            encoding: value.enc_key,
        }
    }
}

impl From<api::Role> for Role {
    fn from(value: api::Role) -> Self {
        match value {
            api::Role::Owner => Role::Owner,
            api::Role::Admin => Role::Admin,
            api::Role::Operator => Role::Operator,
            api::Role::Member => Role::Member,
        }
    }
}

impl From<Role> for api::Role {
    fn from(value: Role) -> Self {
        match value {
            Role::Owner => api::Role::Owner,
            Role::Admin => api::Role::Admin,
            Role::Operator => api::Role::Operator,
            Role::Member => api::Role::Member,
        }
    }
}

impl From<api::ChanOp> for ChanOp {
    fn from(value: api::ChanOp) -> Self {
        match value {
            api::ChanOp::SendRecv => ChanOp::SendRecv,
            api::ChanOp::RecvOnly => ChanOp::RecvOnly,
            api::ChanOp::SendOnly => ChanOp::SendOnly,
        }
    }
}

impl From<ChanOp> for api::ChanOp {
    fn from(value: ChanOp) -> Self {
        match value {
            ChanOp::SendRecv => api::ChanOp::SendRecv,
            ChanOp::RecvOnly => api::ChanOp::RecvOnly,
            ChanOp::SendOnly => api::ChanOp::SendOnly,
        }
    }
}
