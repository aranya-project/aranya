//! Implementation of daemon's `tarpc` API.
//! Trait for API interface is defined in `crates/aranya-daemon-api`

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use core::{future, net::SocketAddr, ops::Deref, pin::pin};
use std::{path::PathBuf, sync::Arc};

use anyhow::{anyhow, Context as _};
use aranya_crypto::{
    default::WrappedKey, policy::GroupId, Csprng, DeviceId, EncryptionKey, EncryptionPublicKey,
    Engine as _, KeyStore as _, KeyStoreExt as _, Rng,
};
pub(crate) use aranya_daemon_api::crypto::ApiKey;
use aranya_daemon_api::{
    self as api,
    crypto::txp::{self, LengthDelimitedCodec},
    DaemonApi, SeedMode, Text, WrappedSeed,
};
use aranya_keygen::PublicKeys;
use aranya_runtime::GraphId;
use aranya_util::{task::scope, Addr};
use futures_util::{StreamExt, TryStreamExt};
pub(crate) use quic_sync::Data as QSData;
use tarpc::{
    context,
    server::{incoming::Incoming, BaseChannel, Channel},
};
use tokio::{net::UnixListener, sync::mpsc};
use tracing::{debug, error, info, instrument, trace, warn, Instrument};

use crate::{
    actions::Actions,
    aqc::Aqc,
    daemon::{CE, CS, KS},
    keystore::LocalStore,
    policy::{ChanOp, Effect, KeyBundle, Role},
    sync::task::{quic as qs, SyncPeers},
    util::SeedDir,
    AranyaStore, Client, InvalidGraphs, EF,
};

mod quic_sync;

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

impl DaemonApiServer {
    /// Creates a `DaemonApiServer`.
    // TODO(eric): Clean up the arguments.
    #[instrument(skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        client: Client,
        local_addr: SocketAddr,
        uds_path: PathBuf,
        sk: ApiKey<CS>,
        pk: PublicKeys<CS>,
        peers: SyncPeers,
        recv_effects: EffectReceiver,
        invalid: InvalidGraphs,
        aqc: Aqc<CE, KS>,
        crypto: Crypto,
        seed_id_dir: SeedDir,
        quic: Option<quic_sync::Data>,
    ) -> anyhow::Result<Self> {
        let listener = UnixListener::bind(&uds_path)?;
        let aqc = Arc::new(aqc);
        let effect_handler = EffectHandler {
            aqc: Arc::clone(&aqc),
        };
        let api = Api(Arc::new(ApiInner {
            client,
            local_addr,
            pk: std::sync::Mutex::new(pk),
            peers,
            effect_handler,
            invalid,
            aqc,
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
    pub(crate) async fn serve(mut self) {
        scope(async |s| {
            s.spawn({
                let effect_handler = self.api.effect_handler.clone();
                async move {
                    while let Some((graph, effects)) = self.recv_effects.recv().await {
                        if let Err(err) = effect_handler.handle_effects(graph, &effects).await {
                            error!(?err, "error handling effects");
                        }
                    }
                    info!("effect handler exiting");
                }
                .in_current_span()
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
                .inspect_err(|err| warn!(?err, "accept error"))
                .filter_map(|r| future::ready(r.ok()))
                .map(BaseChannel::with_defaults)
                .max_concurrent_requests_per_channel(10);
            while let Some(ch) = incoming.next().await {
                let api = self.api.clone();
                s.spawn(scope(async move |reqs| {
                    let requests = ch
                        .requests()
                        .inspect_err(|err| warn!(?err, "channel failure"))
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
    aqc: Arc<Aqc<CE, KS>>,
}

impl EffectHandler {
    /// Handles effects resulting from invoking an Aranya action.
    #[instrument(skip_all, fields(%graph, effects = effects.len()))]
    async fn handle_effects(&self, graph: GraphId, effects: &[Effect]) -> anyhow::Result<()> {
        trace!("handling effects");

        use Effect::*;
        for effect in effects {
            trace!(?effect, "handling effect");
            match effect {
                TeamCreated(_team_created) => {}
                TeamTerminated(_team_terminated) => {}
                MemberAdded(_member_added) => {}
                MemberRemoved(_member_removed) => {}
                OwnerAssigned(_owner_assigned) => {}
                AdminAssigned(_admin_assigned) => {}
                OperatorAssigned(_operator_assigned) => {}
                OwnerRevoked(_owner_revoked) => {}
                AdminRevoked(_admin_revoked) => {}
                OperatorRevoked(_operator_revoked) => {}
                LabelCreated(_) => {}
                LabelDeleted(_) => {}
                LabelAssigned(_) => {}
                LabelRevoked(_) => {}
                AqcNetworkNameSet(e) => {
                    self.aqc
                        .add_peer(
                            graph,
                            api::NetIdentifier(e.net_identifier.clone()),
                            e.device_id.into(),
                        )
                        .await;
                }
                AqcNetworkNameUnset(e) => self.aqc.remove_peer(graph, e.device_id.into()).await,
                QueriedLabel(_) => {}
                AqcBidiChannelCreated(_) => {}
                AqcBidiChannelReceived(_) => {}
                AqcUniChannelCreated(_) => {}
                AqcUniChannelReceived(_) => {}
                QueryDevicesOnTeamResult(_) => {}
                QueryDeviceRoleResult(_) => {}
                QueryDeviceKeyBundleResult(_) => {}
                QueryAqcNetIdentifierResult(_) => {}
                QueriedLabelAssignment(_) => {}
                QueryLabelExistsResult(_) => {}
                QueryAqcNetworkNamesOutput(_) => {}
            }
        }
        Ok(())
    }
}

/// The guts of [`Api`].
///
/// This is separated out so we only have to clone one [`Arc`]
/// (inside [`Api`]).
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
    aqc: Arc<Aqc<CE, KS>>,
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

impl std::fmt::Debug for ApiInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner API Data")
            .field("seed_id_dir", &self.seed_id_dir)
            .field("client", &self.client)
            .field("local_addr", &self.local_addr)
            .field("pk", &self.pk)
            .field("aqc", &self.aqc)
            .finish_non_exhaustive()
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
        if self.invalid.contains(team.into_id().into()) {
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
        self.device_id().map(|id| id.into_id().into())
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
            .add_peer(peer, team.into_id().into(), cfg)
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
            .sync_now(peer, team.into_id().into(), cfg)
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
            .remove_peer(peer, team.into_id().into())
            .await
            .context("unable to remove sync peer")?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn add_team(mut self, _: context::Context, cfg: api::AddTeamConfig) -> api::Result<()> {
        let team = cfg.id;
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
            .remove_graph(team.into_id().into())
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
        let team_id: api::TeamId = graph_id.into_id().into();

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
                .get_key(&mut crypto.engine, enc_pk.id()?.into_id())
                .context("keystore error")?
                .context("missing enc_sk for encrypt seed")?;
            (seed, enc_sk)
        };

        let group = GroupId::from(team.into_id());
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
            .actions(&team.into_id().into())
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
            .actions(&team.into_id().into())
            .remove_member(device.into_id().into())
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
            .actions(&team.into_id().into())
            .assign_role(device.into_id().into(), role.into())
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
            .actions(&team.into_id().into())
            .revoke_role(device.into_id().into(), role.into())
            .await
            .context("unable to revoke device role")?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn assign_aqc_net_identifier(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        name: api::NetIdentifier,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(&team.into_id().into())
            .set_aqc_network_name(device.into_id().into(), name.0)
            .await
            .context("unable to assign aqc network identifier")?;
        self.effect_handler
            .handle_effects(GraphId::from(team.into_id()), &effects)
            .await?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn remove_aqc_net_identifier(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        name: api::NetIdentifier,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

        self.client
            .actions(&team.into_id().into())
            .unset_aqc_network_name(device.into_id().into())
            .await
            .context("unable to remove aqc net identifier")?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn create_aqc_bidi_channel(
        self,
        _: context::Context,
        team: api::TeamId,
        peer: api::NetIdentifier,
        label: api::LabelId,
    ) -> api::Result<(api::AqcCtrl, api::AqcBidiPsks)> {
        self.check_team_valid(team).await?;

        info!("creating bidi channel");

        let graph = GraphId::from(team.into_id());

        let peer_id = self
            .aqc
            .find_device_id(graph, &peer)
            .await
            .context("did not find peer")?;

        let (ctrl, effects) = self
            .client
            .actions(&graph)
            .create_aqc_bidi_channel_off_graph(peer_id, label.into_id().into())
            .await?;
        let id = self.device_id()?;

        let Some(Effect::AqcBidiChannelCreated(e)) =
            find_effect!(&effects, Effect::AqcBidiChannelCreated(e) if e.author_id == id.into())
        else {
            return Err(anyhow!("unable to find `AqcBidiChannelCreated` effect").into());
        };

        self.effect_handler.handle_effects(graph, &effects).await?;

        let psks = self.aqc.bidi_channel_created(e).await?;
        info!(num = psks.len(), "bidi channel created");

        Ok((ctrl, psks))
    }

    #[instrument(skip(self), err)]
    async fn create_aqc_uni_channel(
        self,
        _: context::Context,
        team: api::TeamId,
        peer: api::NetIdentifier,
        label: api::LabelId,
    ) -> api::Result<(api::AqcCtrl, api::AqcUniPsks)> {
        self.check_team_valid(team).await?;

        info!("creating uni channel");

        let graph = GraphId::from(team.into_id());

        let peer_id = self
            .aqc
            .find_device_id(graph, &peer)
            .await
            .context("did not find peer")?;

        let id = self.device_id()?;
        let (ctrl, effects) = self
            .client
            .actions(&graph)
            .create_aqc_uni_channel_off_graph(id, peer_id, label.into_id().into())
            .await?;

        let Some(Effect::AqcUniChannelCreated(e)) =
            find_effect!(&effects, Effect::AqcUniChannelCreated(e) if e.author_id == id.into())
        else {
            return Err(anyhow!("unable to find AqcUniChannelCreated effect").into());
        };

        self.effect_handler.handle_effects(graph, &effects).await?;

        let psks = self.aqc.uni_channel_created(e).await?;
        info!(num = psks.len(), "uni channel created");

        Ok((ctrl, psks))
    }

    #[instrument(skip(self), err)]
    async fn delete_aqc_bidi_channel(
        self,
        _: context::Context,
        chan: api::AqcBidiChannelId,
    ) -> api::Result<api::AqcCtrl> {
        // TODO: remove AQC bidi channel from Aranya.
        todo!();
    }

    #[instrument(skip(self), err)]
    async fn delete_aqc_uni_channel(
        self,
        _: context::Context,
        chan: api::AqcUniChannelId,
    ) -> api::Result<api::AqcCtrl> {
        // TODO: remove AQC uni channel from Aranya.
        todo!();
    }

    #[instrument(skip(self), err)]
    async fn receive_aqc_ctrl(
        self,
        _: context::Context,
        team: api::TeamId,
        ctrl: api::AqcCtrl,
    ) -> api::Result<(api::LabelId, api::AqcPsks)> {
        self.check_team_valid(team).await?;

        let graph = GraphId::from(team.into_id());
        let mut session = self.client.session_new(&graph).await?;
        for cmd in ctrl {
            let our_device_id = self.device_id()?;

            let effects = self.client.session_receive(&mut session, &cmd).await?;
            self.effect_handler.handle_effects(graph, &effects).await?;

            let effect = effects.iter().find(|e| match e {
                Effect::AqcBidiChannelReceived(e) => e.peer_id == our_device_id.into(),
                Effect::AqcUniChannelReceived(e) => {
                    e.sender_id != our_device_id.into() && e.receiver_id == our_device_id.into()
                }
                _ => false,
            });
            match effect {
                Some(Effect::AqcBidiChannelReceived(e)) => {
                    let psks = self.aqc.bidi_channel_received(e).await?;
                    // NB: Each action should only produce one
                    // ephemeral command.
                    return Ok((e.label_id.into(), psks));
                }
                Some(Effect::AqcUniChannelReceived(e)) => {
                    let psks = self.aqc.uni_channel_received(e).await?;
                    // NB: Each action should only produce one
                    // ephemeral command.
                    return Ok((e.label_id.into(), psks));
                }
                Some(_) | None => {}
            }
        }
        Err(anyhow!("unable to find AQC effect").into())
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
    #[instrument(skip(self), err)]
    async fn delete_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label_id: api::LabelId,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

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
    #[instrument(skip(self), err)]
    async fn revoke_label(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label_id: api::LabelId,
    ) -> api::Result<()> {
        self.check_team_valid(team).await?;

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
    #[instrument(skip(self), err)]
    async fn query_devices_on_team(
        self,
        _: context::Context,
        team: api::TeamId,
    ) -> api::Result<Vec<api::DeviceId>> {
        self.check_team_valid(team).await?;

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
    #[instrument(skip(self), err)]
    async fn query_device_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<api::Role> {
        self.check_team_valid(team).await?;

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
    #[instrument(skip(self), err)]
    async fn query_device_keybundle(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<api::KeyBundle> {
        self.check_team_valid(team).await?;

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
    #[instrument(skip(self), err)]
    async fn query_device_label_assignments(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<Vec<api::Label>> {
        self.check_team_valid(team).await?;

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

    /// Query AQC network ID.
    #[instrument(skip(self), err)]
    async fn query_aqc_net_identifier(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<Option<api::NetIdentifier>> {
        self.check_team_valid(team).await?;

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
    #[instrument(skip(self), err)]
    async fn query_label_exists(
        self,
        _: context::Context,
        team: api::TeamId,
        label_id: api::LabelId,
    ) -> api::Result<bool> {
        self.check_team_valid(team).await?;

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

    /// Query list of labels.
    #[instrument(skip(self), err)]
    async fn query_labels(
        self,
        _: context::Context,
        team: api::TeamId,
    ) -> api::Result<Vec<api::Label>> {
        self.check_team_valid(team).await?;

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

impl Api {
    async fn add_seed(&mut self, team: api::TeamId, seed: qs::PskSeed) -> anyhow::Result<()> {
        let crypto = &mut *self.crypto.lock().await;

        let id = seed.id().context("getting seed id")?;

        let wrapped_key = crypto
            .engine
            .wrap(seed.clone().into_inner())
            .context("wrapping seed")?;
        crypto
            .local_store
            .try_insert(id.into_id(), wrapped_key)
            .context("inserting seed")?;

        if let Err(e) = self
            .seed_id_dir
            .append(&team, &id)
            .await
            .context("could not write seed id to file")
        {
            match crypto
                .local_store
                .remove::<WrappedKey<CS>>(id.into_id())
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
