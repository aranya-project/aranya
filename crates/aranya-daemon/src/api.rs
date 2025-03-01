//! Implementation of daemon's `tarpc` API.
//! Trait for API interface is defined in `crates/aranya-daemon-api`

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::{
    future::{self, Future},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use aranya_afc_util::{BidiChannelCreated, BidiChannelReceived, BidiKeys, Handler};
use aranya_buggy::BugExt;
use aranya_crypto::{afc::BidiPeerEncap, keystore::fs_keystore::Store, Csprng, Rng, UserId};
use aranya_daemon_api::{
    AfcCtrl, AfcId, DaemonApi, DeviceId, KeyBundle as ApiKeyBundle, NetIdentifier,
    Result as ApiResult, Role as ApiRole, TeamId, CS,
};
use aranya_fast_channels::{shm::WriteState, AranyaState, ChannelId, Directed, Label, NodeId};
use aranya_keygen::PublicKeys;
use aranya_util::Addr;
use bimap::BiBTreeMap;
use futures_util::{StreamExt, TryStreamExt};
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Json,
};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    aranya::Actions,
    policy::{
        BidiChannelCreated as AfcBidiChannelCreated, BidiChannelReceived as AfcBidiChannelReceived,
        ChanOp, Effect, KeyBundle, Role,
    },
    sync::SyncPeers,
    Client, CE, EF,
};

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

/// Daemon API Server.
///
/// Hosts a `tarpc` server listening on a UDS socket path.
/// The user library will make requests to this API.
pub struct DaemonApiServer {
    daemon_sock: PathBuf,
    /// Channel for receiving effects from the syncer.
    recv_effects: mpsc::Receiver<Vec<EF>>,
    handler: DaemonApiHandler,
}

impl DaemonApiServer {
    /// Create new RPC server.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip_all)]
    pub fn new(
        client: Arc<Client>,
        local_addr: SocketAddr,
        afc: Arc<Mutex<WriteState<CS, Rng>>>,
        eng: CE,
        store: Store,
        daemon_sock: PathBuf,
        pk: Arc<PublicKeys<CS>>,
        peers: SyncPeers,
        recv_effects: mpsc::Receiver<Vec<EF>>,
    ) -> Result<Self> {
        info!("uds path: {:?}", daemon_sock);
        let user_id = pk.ident_pk.id()?;
        Ok(Self {
            daemon_sock,
            recv_effects,
            handler: DaemonApiHandler {
                client,
                local_addr,
                afc,
                eng,
                pk,
                peers,
                afc_peers: Arc::default(),
                handler: Arc::new(Mutex::new(Handler::new(user_id, store))),
            },
        })
    }

    /// Run the RPC server.
    #[instrument(skip_all)]
    #[allow(clippy::disallowed_macros)]
    pub async fn serve(mut self) -> Result<()> {
        let mut listener =
            tarpc::serde_transport::unix::listen(&self.daemon_sock, Json::default).await?;
        info!(
            "listening on {:?}",
            listener
                .local_addr()
                .as_pathname()
                .expect("expected uds api path to be set")
        );
        listener.config_mut().max_frame_length(usize::MAX);
        // TODO: determine if there's a performance benefit to putting these branches in different threads.
        tokio::join!(
            listener
                .inspect_err(|err| warn!(%err, "accept error"))
                // Ignore accept errors.
                .filter_map(|r| future::ready(r.ok()))
                .map(server::BaseChannel::with_defaults)
                // serve is generated by the service attribute. It takes as input any type implementing
                // the generated World trait.
                .map(|channel| {
                    debug!("accepted channel connection");
                    channel
                        .execute(self.handler.clone().serve())
                        .for_each(spawn)
                })
                // Max 10 channels.
                .buffer_unordered(10)
                .for_each(|_| async {}),
            async {
                // receive effects from syncer.
                while let Some(effects) = self.recv_effects.recv().await {
                    // handle effects.
                    if let Err(e) = self.handler.handle_effects(&effects, None).await {
                        error!(?e, "error handling effects");
                    }
                }
            },
        );
        Ok(())
    }
}

#[derive(Clone)]
struct DaemonApiHandler {
    /// Aranya client for
    client: Arc<Client>,
    /// Local socket address of the API.
    local_addr: SocketAddr,
    /// AFC shm write.
    afc: Arc<Mutex<WriteState<CS, Rng>>>,
    /// An implementation of [`Engine`][crypto::Engine].
    eng: CE,
    /// Public keys of current user.
    pk: Arc<PublicKeys<CS>>,
    /// Aranya sync peers,
    peers: SyncPeers,
    /// AFC peers.
    afc_peers: Arc<Mutex<BiBTreeMap<NetIdentifier, UserId>>>,
    /// Handles AFC effects.
    handler: Arc<Mutex<Handler<Store>>>,
}

impl DaemonApiHandler {
    fn get_pk(&self) -> ApiResult<KeyBundle> {
        Ok(KeyBundle::try_from(&*self.pk).context("bad key bundle")?)
    }

    /// Handles effects resulting from invoking an Aranya action.
    #[instrument(skip_all)]
    async fn handle_effects(&self, effects: &[Effect], node_id: Option<NodeId>) -> Result<()> {
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
                Effect::LabelDefined(_label_defined) => {}
                Effect::LabelUndefined(_label_undefined) => {}
                Effect::LabelAssigned(_label_assigned) => {}
                Effect::LabelRevoked(_label_revoked) => {}
                Effect::NetworkNameSet(e) => {
                    self.afc_peers
                        .lock()
                        .await
                        .insert(NetIdentifier(e.net_identifier.clone()), e.user_id.into());
                }
                Effect::NetworkNameUnset(_network_name_unset) => {}
                Effect::BidiChannelCreated(v) => {
                    debug!("received BidiChannelCreated effect");
                    if let Some(node_id) = node_id {
                        self.afc_bidi_channel_created(v, node_id).await?
                    }
                }
                Effect::BidiChannelReceived(v) => {
                    debug!("received BidiChannelReceived effect");
                    if let Some(node_id) = node_id {
                        self.afc_bidi_channel_received(v, node_id).await?
                    }
                }
                // TODO: unidirectional channels
                Effect::UniChannelCreated(_uni_channel_created) => {}
                Effect::UniChannelReceived(_uni_channel_received) => {}
            }
        }
        Ok(())
    }

    /// Reacts to a bidirectional AFC channel being created.
    #[instrument(skip(self), fields(effect = ?v))]
    async fn afc_bidi_channel_created(
        &self,
        v: &AfcBidiChannelCreated,
        node_id: NodeId,
    ) -> Result<()> {
        debug!("received BidiChannelCreated effect");
        // NB: this shouldn't happen because the policy should
        // ensure that label fits inside a `u32`.
        let label = Label::new(u32::try_from(v.label).assume("`label` is out of range")?);
        // TODO: don't clone the eng.
        let BidiKeys { seal, open } = self.handler.lock().await.bidi_channel_created(
            &mut self.eng.clone(),
            &BidiChannelCreated {
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
    async fn afc_bidi_channel_received(
        &self,
        v: &AfcBidiChannelReceived,
        node_id: NodeId,
    ) -> Result<()> {
        // NB: this shouldn't happen because the policy should
        // ensure that label fits inside a `u32`.
        let label = Label::new(u32::try_from(v.label).assume("`label` is out of range")?);
        let BidiKeys { seal, open } = self.handler.lock().await.bidi_channel_received(
            &mut self.eng.clone(),
            &BidiChannelReceived {
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
    async fn aranya_local_addr(self, context: ::tarpc::context::Context) -> ApiResult<SocketAddr> {
        Ok(self.local_addr)
    }

    #[instrument(skip(self))]
    async fn get_key_bundle(self, _: context::Context) -> ApiResult<ApiKeyBundle> {
        Ok(self.get_pk()?.into())
    }

    #[instrument(skip(self))]
    async fn get_device_id(self, _: context::Context) -> ApiResult<DeviceId> {
        Ok(self.pk.ident_pk.id()?.into_id().into())
    }

    #[instrument(skip(self))]
    async fn add_sync_peer(
        self,
        _: context::Context,
        peer: Addr,
        team: TeamId,
        interval: Duration,
    ) -> ApiResult<()> {
        self.peers
            .add_peer(peer, interval, team.into_id().into())
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_sync_peer(
        self,
        _: context::Context,
        peer: Addr,
        team: TeamId,
    ) -> ApiResult<()> {
        self.peers.remove_peer(peer, team.into_id().into()).await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn add_team(self, _: context::Context, team: TeamId) -> ApiResult<()> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn remove_team(self, _: context::Context, team: TeamId) -> ApiResult<()> {
        todo!();
    }

    #[instrument(skip(self))]
    async fn create_team(self, _: context::Context) -> ApiResult<TeamId> {
        info!("create_team");
        let nonce = &mut [0u8; 16];
        Rng.fill_bytes(nonce);
        let pk = self.get_pk()?;
        let (graph_id, _) = self.client.create_team(pk, Some(nonce)).await?;
        debug!(?graph_id);
        Ok(graph_id.into_id().into())
    }

    #[instrument(skip(self))]
    async fn close_team(self, _: context::Context, team: TeamId) -> ApiResult<()> {
        todo!();
    }

    #[instrument(skip(self))]
    async fn add_device_to_team(
        self,
        _: context::Context,
        team: TeamId,
        keys: ApiKeyBundle,
    ) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .add_member(keys.into())
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_device_from_team(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
    ) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .remove_member(device.into_id().into())
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn assign_role(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        role: ApiRole,
    ) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .assign_role(device.into_id().into(), role.into())
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn revoke_role(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        role: ApiRole,
    ) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .revoke_role(device.into_id().into(), role.into())
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn assign_net_identifier(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> ApiResult<()> {
        let effects = self
            .client
            .actions(&team.into_id().into())
            .set_network_name(device.into_id().into(), name.0)
            .await?;
        self.handle_effects(&effects, None).await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_net_identifier(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .unset_network_name(device.into_id().into())
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn create_label(self, _: context::Context, team: TeamId, label: Label) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .define_label(label)
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_label(self, _: context::Context, team: TeamId, label: Label) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .undefine_label(label)
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn assign_label(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        label: Label,
    ) -> ApiResult<()> {
        // TODO: support other channel permissions.
        self.client
            .actions(&team.into_id().into())
            .assign_label(device.into_id().into(), label, ChanOp::ReadWrite)
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn revoke_label(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        label: Label,
    ) -> ApiResult<()> {
        let id = self.pk.ident_pk.id()?;
        self.client
            .actions(&team.into_id().into())
            .revoke_label(id, label)
            .await?;
        Ok(())
    }

    #[instrument(skip_all)]
    async fn create_bidi_channel(
        self,
        _: context::Context,
        team: TeamId,
        peer: NetIdentifier,
        node_id: NodeId,
        label: Label,
    ) -> ApiResult<(AfcId, AfcCtrl)> {
        info!("create_bidi_channel");

        let peer_id = self
            .afc_peers
            .lock()
            .await
            .get_by_left(&peer)
            .copied()
            .context("unable to lookup peer")?;

        let (ctrl, effects) = self
            .client
            .actions(&team.into_id().into())
            .create_bidi_channel_off_graph(peer_id, label)
            .await?;
        let id = self.pk.ident_pk.id()?;

        let Some(Effect::BidiChannelCreated(e)) =
            find_effect!(&effects, Effect::BidiChannelCreated(e) if e.author_id == id.into())
        else {
            return Err(anyhow::anyhow!("unable to find BidiChannelCreated effect").into());
        };
        let afc_id: AfcId = e.channel_key_id.into();
        debug!(?afc_id, "processed afc ID");

        self.handle_effects(&effects, Some(node_id)).await?;
        Ok((afc_id, ctrl))
    }

    #[instrument(skip(self))]
    async fn delete_channel(self, _: context::Context, chan: AfcId) -> ApiResult<AfcCtrl> {
        // TODO: remove AFC channel from Aranya.
        todo!();
    }

    #[instrument(skip_all)]
    async fn receive_afc_ctrl(
        self,
        _: context::Context,
        team: TeamId,
        node_id: NodeId,
        ctrl: AfcCtrl,
    ) -> ApiResult<(AfcId, NetIdentifier, Label)> {
        let mut session = self.client.session_new(&team.into_id().into()).await?;
        for cmd in ctrl {
            let effects = self.client.session_receive(&mut session, &cmd).await?;
            let id = self.pk.ident_pk.id()?;
            self.handle_effects(&effects, Some(node_id)).await?;
            let Some(Effect::BidiChannelReceived(e)) =
                find_effect!(&effects, Effect::BidiChannelReceived(e) if e.peer_id == id.into())
            else {
                continue;
            };
            let encap = BidiPeerEncap::<CS>::from_bytes(&e.encap).context("unable to get encap")?;
            let afc_id: AfcId = encap.id().into();
            debug!(?afc_id, "processed afc ID");
            let label = Label::new(e.label.try_into().expect("expected label conversion"));
            let net = self
                .afc_peers
                .lock()
                .await
                .get_by_right(&e.author_id.into())
                .context("missing net identifier for channel author")?
                .clone();
            return Ok((afc_id, net, label));
        }
        Err(anyhow!("unable to find BidiChannelReceived effect").into())
    }
}

impl From<ApiKeyBundle> for KeyBundle {
    fn from(value: ApiKeyBundle) -> Self {
        KeyBundle {
            ident_key: value.identity,
            sign_key: value.signing,
            enc_key: value.encoding,
        }
    }
}

impl From<KeyBundle> for ApiKeyBundle {
    fn from(value: KeyBundle) -> Self {
        ApiKeyBundle {
            identity: value.ident_key,
            signing: value.sign_key,
            encoding: value.enc_key,
        }
    }
}

impl From<ApiRole> for Role {
    fn from(value: ApiRole) -> Self {
        match value {
            ApiRole::Owner => Role::Owner,
            ApiRole::Admin => Role::Admin,
            ApiRole::Operator => Role::Operator,
            ApiRole::Member => Role::Member,
        }
    }
}
