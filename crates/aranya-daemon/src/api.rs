//! Implementation of daemon's `tarpc` API.
//! Trait for API interface is defined in `crates/aranya-daemon-api`

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use core::{future, net::SocketAddr, ops::Deref, pin::pin};
use std::{path::PathBuf, sync::Arc};

use anyhow::{anyhow, Context as _};
use aranya_crypto::{
    default::WrappedKey,
    policy::{GroupId, LabelId},
    Csprng, DeviceId, EncryptionKey, EncryptionPublicKey, KeyStore as _, KeyStoreExt as _, Rng,
};
pub(crate) use aranya_daemon_api::crypto::ApiKey;
use aranya_daemon_api::{
    self as api,
    crypto::txp::{self, LengthDelimitedCodec},
    DaemonApi, Text, WrappedSeed,
};
use aranya_keygen::PublicKeys;
use aranya_runtime::GraphId;
use aranya_util::{error::ReportExt as _, ready, task::scope, Addr};
#[cfg(feature = "afc")]
use buggy::bug;
use derive_where::derive_where;
use futures_util::{StreamExt, TryStreamExt};
pub(crate) use quic_sync::Data as QSData;
use tarpc::{
    context,
    server::{incoming::Incoming, BaseChannel, Channel},
};
use tokio::{net::UnixListener, sync::mpsc};
use tracing::{debug, error, info, instrument, trace, warn};

#[cfg(feature = "afc")]
use crate::afc::{Afc, RemoveIfParams};
use crate::{
    daemon::{CE, CS, KS},
    keystore::LocalStore,
    policy::{ChanOp, Effect, KeyBundle, Role},
    sync::task::{quic as qs, SyncPeers},
    util::SeedDir,
    AranyaStore, Client, InvalidGraphs, EF,
};

mod quic_sync;

pub(crate) type EffectReceiver = mpsc::Receiver<(GraphId, Vec<EF>)>;

/// Daemon API Server.
#[derive(Debug)]
pub(crate) struct DaemonApiServer {
    /// Used to encrypt data sent over the API.
    sk: ApiKey<CS>,
    /// The UDS path we serve the API on.
    uds_path: PathBuf,
    /// Socket bound to `uds_path`.
    listener: UnixListener,

    /// Channel for receiving effects from the syncer.
    recv_effects: EffectReceiver,

    /// Api Handler.
    api: Api,
}

pub(crate) struct DaemonApiServerArgs {
    pub(crate) client: Client,
    pub(crate) local_addr: SocketAddr,
    pub(crate) uds_path: PathBuf,
    pub(crate) sk: ApiKey<CS>,
    pub(crate) pk: PublicKeys<CS>,
    pub(crate) peers: SyncPeers,
    pub(crate) recv_effects: EffectReceiver,
    pub(crate) invalid: InvalidGraphs,
    #[cfg(feature = "afc")]
    pub(crate) afc: Afc<CE, CS, KS>,
    pub(crate) crypto: Crypto,
    pub(crate) seed_id_dir: SeedDir,
    pub(crate) quic: Option<quic_sync::Data>,
}

impl DaemonApiServer {
    /// Creates a `DaemonApiServer`.
    #[instrument(skip_all)]
    pub(crate) fn new(
        DaemonApiServerArgs {
            client,
            local_addr,
            uds_path,
            sk,
            pk,
            peers,
            recv_effects,
            invalid,
            #[cfg(feature = "afc")]
            afc,
            crypto,
            seed_id_dir,
            quic,
        }: DaemonApiServerArgs,
    ) -> anyhow::Result<Self> {
        let listener = UnixListener::bind(&uds_path)?;
        let uds_path = uds_path
            .canonicalize()
            .context("could not canonicalize uds_path")?;
        #[cfg(feature = "afc")]
        let afc = Arc::new(afc);
        let effect_handler = EffectHandler {
            #[cfg(feature = "afc")]
            afc: afc.clone(),
            #[cfg(feature = "afc")]
            device_id: pk.ident_pk.id()?,
        };
        let api = Api(Arc::new(ApiInner {
            client,
            local_addr,
            pk: std::sync::Mutex::new(pk),
            peers,
            effect_handler,
            invalid,
            #[cfg(feature = "afc")]
            afc,
            crypto: tokio::sync::Mutex::new(crypto),
            seed_id_dir,
            quic,
        }));
        Ok(Self {
            uds_path,
            sk,
            recv_effects,
            listener,
            api,
        })
    }

    /// Runs the server.
    pub(crate) async fn serve(mut self, ready: ready::Notifier) {
        scope(async |s| {
            s.spawn({
                let effect_handler = self.api.effect_handler.clone();
                async move {
                    while let Some((graph, effects)) = self.recv_effects.recv().await {
                        if let Err(err) = effect_handler.handle_effects(graph, &effects).await {
                            error!(error = ?err, "error handling effects");
                        }
                    }
                    info!("effect handler exiting");
                }
            });

            let server = {
                let info = self.uds_path.as_os_str().as_encoded_bytes();
                let codec = LengthDelimitedCodec::builder()
                    .max_frame_length(usize::MAX)
                    .new_codec();
                let listener = txp::unix::UnixListenerStream::from(self.listener);
                txp::server(listener, codec, self.sk, info)
            };
            info!(path = ?self.uds_path, "listening");

            let mut incoming = server
                .inspect_err(|err| warn!(error = %err.report(), "accept error"))
                .filter_map(|r| future::ready(r.ok()))
                .map(BaseChannel::with_defaults)
                .max_concurrent_requests_per_channel(10);

            ready.notify();

            while let Some(ch) = incoming.next().await {
                let api = self.api.clone();
                s.spawn(scope(async move |reqs| {
                    let requests = ch
                        .requests()
                        .inspect_err(|err| warn!(error = %err.report(), "channel failure"))
                        .take_while(|r| future::ready(r.is_ok()))
                        .filter_map(|r| async { r.ok() });
                    let mut requests = pin!(requests);
                    while let Some(req) = requests.next().await {
                        reqs.spawn(req.execute(api.clone().serve()));
                    }
                }));
            }
        })
        .await;

        info!("server exiting");
    }
}

/// Handles effects from an Aranya action.
#[derive(Clone, Debug)]
struct EffectHandler {
    #[cfg(feature = "afc")]
    afc: Arc<Afc<CE, CS, KS>>,
    #[cfg(feature = "afc")]
    device_id: DeviceId,
}

impl EffectHandler {
    /// Handles effects resulting from invoking an Aranya action.
    #[instrument(skip_all, fields(%graph, effects = effects.len()))]
    async fn handle_effects(&self, graph: GraphId, effects: &[Effect]) -> anyhow::Result<()> {
        trace!("handling effects");

        use Effect::*;
        // TODO: support feature flag in interface generator to compile out certain effects.
        for effect in effects {
            trace!(?effect, "handling effect");
            match effect {
                TeamCreated(_team_created) => {}
                TeamTerminated(_team_terminated) => {
                    #[cfg(feature = "afc")]
                    self.afc.delete_channels().await?;
                }
                MemberAdded(_member_added) => {}
                MemberRemoved(_member_removed) => {
                    #[cfg(feature = "afc")]
                    {
                        let removed_member = DeviceId::from_base(_member_removed.device_id);
                        if self.device_id == removed_member {
                            self.afc.delete_channels().await?;
                        } else {
                            self.afc
                                .remove_if(RemoveIfParams {
                                    peer_id: Some(removed_member),
                                    ..Default::default()
                                })
                                .await?;
                        }
                    }
                }
                OwnerAssigned(_owner_assigned) => {}
                AdminAssigned(_admin_assigned) => {}
                OperatorAssigned(_operator_assigned) => {}
                OwnerRevoked(_owner_revoked) => {}
                AdminRevoked(_admin_revoked) => {}
                OperatorRevoked(_operator_revoked) => {}
                LabelCreated(_) => {}
                LabelDeleted(_label_deleted) => {
                    #[cfg(feature = "afc")]
                    self.afc
                        .remove_if(RemoveIfParams {
                            label_id: Some(LabelId::from_base(_label_deleted.label_id)),
                            ..Default::default()
                        })
                        .await?;
                }
                LabelAssigned(_) => {}
                LabelRevoked(_label_revoked) => {
                    #[cfg(feature = "afc")]
                    {
                        let label_id = Some(LabelId::from_base(_label_revoked.label_id));
                        let peer_id = Some(DeviceId::from_base(_label_revoked.device_id))
                            .filter(|&id| id != self.device_id);
                        self.afc
                            .remove_if(RemoveIfParams {
                                label_id,
                                peer_id,
                                ..Default::default()
                            })
                            .await?;
                    }
                }
                QueriedLabel(_) => {}
                AfcUniChannelCreated(_) => {}
                AfcUniChannelReceived(_) => {}
                QueryDevicesOnTeamResult(_) => {}
                QueryDeviceRoleResult(_) => {}
                QueryDeviceKeyBundleResult(_) => {}
                QueriedLabelAssignment(_) => {}
                QueryLabelExistsResult(_) => {}
            }
        }
        Ok(())
    }
}

/// The guts of [`Api`].
///
/// This is separated out so we only have to clone one [`Arc`]
/// (inside [`Api`]).
#[derive_where(Debug)]
struct ApiInner {
    client: Client,
    /// Local socket address of the API.
    local_addr: SocketAddr,
    /// Public keys of current device.
    pk: std::sync::Mutex<PublicKeys<CS>>,
    /// Aranya sync peers,
    peers: SyncPeers,
    /// Handles graph effects from the syncer.
    effect_handler: EffectHandler,
    /// Keeps track of which graphs are invalid due to a finalization error.
    invalid: InvalidGraphs,
    #[cfg(feature = "afc")]
    afc: Arc<Afc<CE, CS, KS>>,
    #[derive_where(skip(Debug))]
    crypto: tokio::sync::Mutex<Crypto>,
    seed_id_dir: SeedDir,
    quic: Option<quic_sync::Data>,
}

pub(crate) struct Crypto {
    pub(crate) engine: CE,
    pub(crate) local_store: LocalStore<KS>,
    pub(crate) aranya_store: AranyaStore<KS>,
}

impl ApiInner {
    fn get_pk(&self) -> api::Result<KeyBundle> {
        let pk = self.pk.lock().expect("poisoned");
        Ok(KeyBundle::try_from(&*pk).context("bad key bundle")?)
    }

    fn device_id(&self) -> api::Result<DeviceId> {
        let pk = self.pk.lock().expect("poisoned");
        let id = pk.ident_pk.id()?;
        Ok(id)
    }
}

/// Implements [`DaemonApi`].
#[derive(Clone, Debug)]
struct Api(Arc<ApiInner>);

impl Deref for Api {
    type Target = ApiInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Api {
    /// Checks wither a team's graph is valid.
    /// If the graph is not valid, return an error to prevent operations on the invalid graph.
    async fn check_team_valid(&self, team: api::TeamId) -> anyhow::Result<()> {
        if self.invalid.contains(GraphId::transmute(team)) {
            // TODO: return custom daemon error type
            anyhow::bail!("team {team} invalid due to graph finalization error")
        }
        Ok(())
    }
}

impl DaemonApi for Api {
    #[instrument(skip(self), err)]
    async fn version(self, context: context::Context) -> api::Result<api::Version> {
        api::Version::parse(env!("CARGO_PKG_VERSION")).map_err(Into::into)
    }

    #[instrument(skip(self), err)]
    async fn aranya_local_addr(self, context: context::Context) -> api::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    #[instrument(skip(self), err)]
    async fn get_key_bundle(self, _: context::Context) -> api::Result<api::KeyBundle> {
        Ok(self
            .get_pk()
            .context("unable to get device public keys")?
            .into())
    }

    #[instrument(skip(self), err)]
    async fn get_device_id(self, _: context::Context) -> api::Result<api::DeviceId> {
        self.device_id().map(api::DeviceId::transmute)
    }

    #[cfg(feature = "afc")]
    #[instrument(skip(self), err)]
    async fn afc_shm_info(self, context: context::Context) -> api::Result<api::AfcShmInfo> {
        Ok(self.afc.get_shm_info().await)
    }

    #[instrument(skip(self), err)]
    async fn add_sync_peer(
        self,
        _: context::Context,
        peer: Addr,
        team: api::TeamId,
        cfg: api::SyncPeerConfig,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.peers
            .add_peer(peer, GraphId::transmute(team), cfg)
            .await?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn sync_now(
        self,
        _: context::Context,
        peer: Addr,
        team: api::TeamId,
        cfg: Option<api::SyncPeerConfig>,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.peers
            .sync_now(peer, GraphId::transmute(team), cfg)
            .await?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn remove_sync_peer(
        self,
        _: context::Context,
        peer: Addr,
        team: api::TeamId,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.peers
            .remove_peer(peer, GraphId::transmute(team))
            .await
            .context("unable to remove sync peer")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn add_team(mut self, _: context::Context, cfg: api::AddTeamConfig) -> api::Result<()> {
        let team = cfg.team_id;
        self.check_team_valid(team).await?;

        match cfg.quic_sync {
            Some(cfg) => self.add_team_quic_sync(team, cfg).await,
            None => Err(anyhow!("Missing QUIC sync config").into()),
        }
    }

    #[instrument(skip(self), err)]
    async fn remove_team(self, _: context::Context, team: api::TeamId) -> api::Result<()> {
        if let Some(data) = &self.quic {
            self.remove_team_quic_sync(team, data)?;
        }

        self.seed_id_dir.remove(&team).await?;

        self.client
            .aranya
            .lock()
            .await
            .remove_graph(GraphId::transmute(team))
            .context("unable to remove graph from storage")?;

        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn create_team(
        mut self,
        _: context::Context,
        cfg: api::CreateTeamConfig,
    ) -> api::Result<api::TeamId> {
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
        let team_id = api::TeamId::transmute(graph_id);

        match cfg.quic_sync {
            Some(qs_cfg) => {
                self.create_team_quic_sync(team_id, qs_cfg).await?;
            }
            None => {
                warn!("Missing QUIC sync config");

                let seed = qs::PskSeed::new(&mut Rng, team_id);
                self.add_seed(team_id, seed).await?;
            }
        }

        Ok(team_id)
    }

    #[instrument(skip(self), err)]
    async fn close_team(self, _: context::Context, team: api::TeamId) -> api::Result<()> {
        self.check_team_valid(team).await?;

        todo!();
    }

    #[instrument(skip(self), err)]
    async fn encrypt_psk_seed_for_peer(
        self,
        _: context::Context,
        team: api::TeamId,
        peer_enc_pk: EncryptionPublicKey<CS>,
    ) -> aranya_daemon_api::Result<WrappedSeed> {
        let enc_pk = self.pk.lock().expect("poisoned").enc_pk.clone();

        let (seed, enc_sk) = {
            let crypto = &mut *self.crypto.lock().await;
            let seed = {
                let seed_id = self.seed_id_dir.get(&team).await?;
                qs::PskSeed::load(&mut crypto.engine, &crypto.local_store, &seed_id)?
                    .context("no seed in dir")?
            };
            let enc_sk: EncryptionKey<CS> = crypto
                .aranya_store
                .get_key(&mut crypto.engine, enc_pk.id()?)
                .context("keystore error")?
                .context("missing enc_sk for encrypt seed")?;
            (seed, enc_sk)
        };

        let group = GroupId::transmute(team);
        let (encap_key, encrypted_seed) = enc_sk
            .seal_psk_seed(&mut Rng, &seed.0, &peer_enc_pk, &group)
            .context("could not seal psk seed")?;

        Ok(WrappedSeed {
            sender_pk: enc_pk,
            encap_key,
            encrypted_seed,
        })
    }

    #[instrument(skip(self), err)]
    async fn add_device_to_team(
        self,
        _: context::Context,
        team: api::TeamId,
        keys: api::KeyBundle,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.client
            .actions(&GraphId::transmute(team))
            .add_member(keys.into())
            .await
            .context("unable to add device to team")?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn remove_device_from_team(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.client
            .actions(&GraphId::transmute(team))
            .remove_member(DeviceId::transmute(device))
            .await
            .context("unable to remove device from team")?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn assign_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        role: api::Role,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.client
            .actions(&GraphId::transmute(team))
            .assign_role(DeviceId::transmute(device), role.into())
            .await
            .context("unable to assign role")?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn revoke_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        role: api::Role,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.client
            .actions(&GraphId::transmute(team))
            .revoke_role(DeviceId::transmute(device), role.into())
            .await
            .context("unable to revoke device role")?;
        Ok(())
    }

    #[cfg(feature = "afc")]
    #[instrument(skip(self), err)]
    async fn create_afc_uni_send_channel(
        self,
        _: context::Context,
        team: api::TeamId,
        peer_id: api::DeviceId,
        label: api::LabelId,
    ) -> api::Result<(api::AfcCtrl, api::AfcLocalChannelId, api::AfcChannelId)> {
        use aranya_crypto::policy::LabelId;

        self.check_team_valid(team).await?;

        info!("creating afc uni channel");

        let graph = GraphId::transmute(team);

        let (ctrl, effects) = self
            .client
            .ephemeral_actions(&graph)
            .create_afc_uni_channel(DeviceId::transmute(peer_id), LabelId::transmute(label))
            .await?;

        let [Effect::AfcUniChannelCreated(e)] = effects.as_slice() else {
            bug!("expected afc uni channel created effect")
        };

        self.effect_handler.handle_effects(graph, &effects).await?;

        let (local_channel_id, channel_id) = self.afc.uni_channel_created(e).await?;
        info!("afc uni channel created");

        let ctrl = get_afc_ctrl(ctrl)?;

        Ok((ctrl, local_channel_id, channel_id))
    }

    #[cfg(feature = "afc")]
    #[instrument(skip(self), err)]
    async fn delete_afc_channel(
        self,
        _: context::Context,
        chan: api::AfcLocalChannelId,
    ) -> api::Result<()> {
        self.afc.delete_channel(chan).await?;
        info!("afc channel deleted");
        Ok(())
    }

    #[cfg(feature = "afc")]
    #[instrument(skip(self), err)]
    async fn receive_afc_ctrl(
        self,
        _: context::Context,
        team: api::TeamId,
        ctrl: api::AfcCtrl,
    ) -> api::Result<(api::LabelId, api::AfcLocalChannelId, api::AfcChannelId)> {
        self.check_team_valid(team).await?;

        let graph = GraphId::transmute(team);
        let mut session = self.client.session_new(&graph).await?;

        let effects = self.client.session_receive(&mut session, &ctrl).await?;

        let [Effect::AfcUniChannelReceived(e)] = effects.as_slice() else {
            bug!("expected afc uni channel received effect")
        };

        self.effect_handler.handle_effects(graph, &effects).await?;

        let (local_channel_id, channel_id) = self.afc.uni_channel_received(e).await?;

        return Ok((
            api::LabelId::transmute(e.label_id),
            local_channel_id,
            channel_id,
        ));
    }

    /// Create a label.
    #[instrument(skip(self), err)]
    async fn create_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label_name: Text,
    ) -> api::Result<api::LabelId> {
        self.check_team_valid(team).await?;

        let effect = self
            .client
            .actions(&GraphId::transmute(team))
            .create_label(label_name)
            .await
            .context("unable to create label")?;

        Ok(api::LabelId::transmute(effect.label_id))
    }

    /// Delete a label.
    #[instrument(skip(self), err)]
    async fn delete_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label_id: api::LabelId,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.client
            .actions(&GraphId::transmute(team))
            .delete_label(LabelId::transmute(label_id))
            .await
            .context("unable to delete label")?;

        Ok(())
    }

    /// Assign a label.
    #[instrument(skip(self), err)]
    async fn assign_label(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label_id: api::LabelId,
        op: api::ChanOp,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.client
            .actions(&GraphId::transmute(team))
            .assign_label(
                DeviceId::transmute(device),
                LabelId::transmute(label_id),
                op.into(),
            )
            .await
            .context("unable to assign label")?;

        Ok(())
    }

    /// Revoke a label.
    #[instrument(skip(self), err)]
    async fn revoke_label(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label_id: api::LabelId,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.client
            .actions(&GraphId::transmute(team))
            .revoke_label(DeviceId::transmute(device), LabelId::transmute(label_id))
            .await
            .context("unable to revoke label")?;

        Ok(())
    }

    /// Query devices on team.
    #[instrument(skip(self), err)]
    async fn query_devices_on_team(
        self,
        _: context::Context,
        team: api::TeamId,
    ) -> api::Result<Vec<api::DeviceId>> {
        self.check_team_valid(team).await?;

        let effects = self
            .client
            .queries(&GraphId::transmute(team))
            .query_devices_on_team()
            .await
            .context("unable to query devices on team")?;

        Ok(effects
            .into_iter()
            .map(|e| api::DeviceId::transmute(e.device_id))
            .collect())
    }

    /// Query device role.
    #[instrument(skip(self), err)]
    async fn query_device_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<api::Role> {
        self.check_team_valid(team).await?;

        let effect = self
            .client
            .queries(&GraphId::transmute(team))
            .query_device_role(DeviceId::transmute(device))
            .await
            .context("unable to query device role")?;

        Ok(api::Role::from(effect.role))
    }
    /// Query device keybundle.
    #[instrument(skip(self), err)]
    async fn query_device_keybundle(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<api::KeyBundle> {
        self.check_team_valid(team).await?;

        let effect = self
            .client
            .queries(&GraphId::transmute(team))
            .query_device_keybundle(DeviceId::transmute(device))
            .await
            .context("unable to query device keybundle")?;

        Ok(api::KeyBundle::from(effect.device_keys))
    }

    /// Query device label assignments.
    #[instrument(skip(self), err)]
    async fn query_device_label_assignments(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<Vec<api::Label>> {
        self.check_team_valid(team).await?;

        let effects = self
            .client
            .queries(&GraphId::transmute(team))
            .query_label_assignments(DeviceId::transmute(device))
            .await
            .context("unable to query device label assignments")?;

        Ok(effects
            .into_iter()
            .map(|e| api::Label {
                id: api::LabelId::transmute(e.label_id),
                name: e.label_name,
            })
            .collect())
    }

    /// Query label exists.
    #[instrument(skip(self), err)]
    async fn query_label_exists(
        self,
        _: context::Context,
        team: api::TeamId,
        label_id: api::LabelId,
    ) -> api::Result<bool> {
        self.check_team_valid(team).await?;

        let _effect = self
            .client
            .queries(&GraphId::transmute(team))
            .query_label_exists(LabelId::transmute(label_id))
            .await
            .context("unable to query label")?;

        Ok(true)
    }

    /// Query list of labels.
    #[instrument(skip(self), err)]
    async fn query_labels(
        self,
        _: context::Context,
        team: api::TeamId,
    ) -> api::Result<Vec<api::Label>> {
        self.check_team_valid(team).await?;

        let effects = self
            .client
            .queries(&GraphId::transmute(team))
            .query_labels()
            .await
            .context("unable to query labels")?;

        Ok(effects
            .into_iter()
            .map(|e| api::Label {
                id: api::LabelId::transmute(e.label_id),
                name: e.label_name,
            })
            .collect())
    }
}

impl Api {
    async fn add_seed(&mut self, team: api::TeamId, seed: qs::PskSeed) -> anyhow::Result<()> {
        let crypto = &mut *self.crypto.lock().await;

        let id = crypto
            .local_store
            .insert_key(&mut crypto.engine, seed.into_inner())
            .context("inserting seed")?;

        if let Err(e) = self
            .seed_id_dir
            .append(&team, &id)
            .await
            .context("could not write seed id to file")
        {
            match crypto
                .local_store
                .remove::<WrappedKey<CS>>(id.as_base())
                .context("could not remove seed from keystore")
            {
                Ok(_) => return Err(e),
                Err(inner) => return Err(e).context(inner),
            }
        };

        Ok(())
    }
}

impl From<api::KeyBundle> for KeyBundle {
    fn from(value: api::KeyBundle) -> Self {
        KeyBundle {
            ident_key: value.identity,
            sign_key: value.signing,
            enc_key: value.encryption,
        }
    }
}

impl From<KeyBundle> for api::KeyBundle {
    fn from(value: KeyBundle) -> Self {
        api::KeyBundle {
            identity: value.ident_key,
            signing: value.sign_key,
            encryption: value.enc_key,
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

/// Extract a single command from the session commands to get the AFC control message.
#[cfg(feature = "afc")]
fn get_afc_ctrl(cmds: Vec<Box<[u8]>>) -> anyhow::Result<Box<[u8]>> {
    let mut cmds = cmds.into_iter();
    let msg = cmds.next().context("missing AFC control message")?;
    if cmds.next().is_some() {
        anyhow::bail!("too many commands for AFC control message");
    }
    Ok(msg)
}
