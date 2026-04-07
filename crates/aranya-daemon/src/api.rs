//! Implementation of daemon's `tarpc` API.
//! Trait for API interface is defined in `crates/aranya-daemon-api`

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use core::{future, ops::Deref, pin::pin};
#[cfg(feature = "preview")]
use std::{collections::HashMap, time::Duration};
use std::{path::PathBuf, sync::Arc};

use anyhow::{anyhow, Context as _};
use aranya_crypto::{
    policy::{LabelId, RoleId},
    Csprng, DeviceId, Rng,
};
pub(crate) use aranya_daemon_api::crypto::ApiKey;
use aranya_daemon_api::{
    self as api,
    crypto::txp::{self, LengthDelimitedCodec},
    DaemonApi, Text,
};
use aranya_keygen::PublicKeys;
use aranya_runtime::GraphId;
#[cfg(feature = "preview")]
use aranya_runtime::{Address, Storage, StorageProvider};
use aranya_util::{error::ReportExt as _, ready, task::scope, Addr};
#[cfg(feature = "afc")]
use buggy::bug;
use derive_where::derive_where;
use futures_util::{StreamExt, TryStreamExt};
use tarpc::{
    context,
    server::{incoming::Incoming, BaseChannel, Channel},
};
#[cfg(feature = "preview")]
use tokio::sync::Mutex;
use tokio::{net::UnixListener, sync::mpsc};
use tracing::{debug, error, info, instrument, trace, warn};

use crate::{
    actions::Actions,
    daemon::CS,
    policy::{ChanOp, Effect, Perm, PublicKeyBundle, RoleCreated},
    sync::{SyncHandle, SyncPeer},
    util::TeamConfigStore,
    Client, EF,
};
#[cfg(feature = "afc")]
use crate::{
    actions::SessionData,
    afc::Afc,
    daemon::{CE, KS},
};

/// Find the first effect matching a given pattern.
///
/// Returns `None` if there are no matching effects.
#[macro_export]
macro_rules! find_effect {
    ($effects:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {
        $effects.into_iter().find(|e| matches!(e, $pattern $(if $guard)?))
    }
}

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
    recv_effects: mpsc::Receiver<(GraphId, Vec<EF>)>,

    /// Api Handler.
    api: Api,
}

pub(crate) struct DaemonApiServerArgs {
    pub(crate) client: Client,
    pub(crate) local_addr: Addr,
    pub(crate) uds_path: PathBuf,
    pub(crate) sk: ApiKey<CS>,
    pub(crate) pk: PublicKeys<CS>,
    pub(crate) syncer: SyncHandle,
    pub(crate) recv_effects: mpsc::Receiver<(GraphId, Vec<EF>)>,
    #[cfg(feature = "afc")]
    pub(crate) afc: Afc<CE, CS, KS>,
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
            syncer,
            recv_effects,
            #[cfg(feature = "afc")]
            afc,
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
            #[cfg(feature = "preview")]
            client: client.clone(),
            #[cfg(feature = "preview")]
            syncer: syncer.clone(),
            #[cfg(feature = "preview")]
            prev_head_addresses: Arc::default(),
        };
        let api = Api(Arc::new(ApiInner {
            client,
            local_addr,
            pk: std::sync::Mutex::new(pk),
            syncer,
            effect_handler,
            #[cfg(feature = "afc")]
            afc,
            teams: TeamConfigStore::new(),
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
    #[cfg(feature = "preview")]
    client: Client,
    #[cfg(feature = "preview")]
    syncer: SyncHandle,
    /// Stores the previous head address for each graph to detect changes
    #[cfg(feature = "preview")]
    prev_head_addresses: Arc<Mutex<HashMap<GraphId, Address>>>,
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
                TeamCreated(_) => {}
                TeamTerminated(_) => {}
                DeviceAdded(_) => {}
                DeviceRemoved(_) => {}
                RoleAssigned(_) => {}
                RoleRevoked(_) => {}
                LabelCreated(_) => {}
                LabelDeleted(_) => {}
                AssignedLabelToDevice(_) => {}
                LabelRevokedFromDevice(_) => {}
                QueryLabelResult(_) => {}
                AfcUniChannelCreated(_) => {}
                AfcUniChannelReceived(_) => {}
                QueryDevicesOnTeamResult(_) => {}
                QueryDeviceRoleResult(_) => {}
                QueryDeviceKeyBundleResult(_) => {}
                QueryLabelsAssignedToDeviceResult(_) => {}
                PermAddedToRole(_) => {}
                PermRemovedFromRole(_) => {}
                RoleChanged(_) => {}
                QueryLabelsResult(_) => {}
                QueryTeamRolesResult(_) => {}
                QueryAfcChannelIsValidResult(_) => {}
                QueryRoleHasPermResult(_) => {}
                QueryRolePermsResult(_) => {}
                QueryRankResult(_) => {}
                QueryDeviceGenerationResult(_) => {}
                RankChanged(_) => {}
                RoleCreated(_) => {}
                RoleDeleted(_) => {}
                CheckValidAfcChannels(_) => {
                    #[cfg(feature = "afc")]
                    self.afc
                        .remove_invalid_channels(graph, self.device_id)
                        .await?;
                }
            }
        }

        #[cfg(feature = "preview")]
        {
            // Check if the graph head address has changed
            let Some(current_head) = self.get_graph_head_address(graph).await else {
                warn!(?graph, "unable to get current graph head address");
                return Ok(());
            };

            let mut prev_addresses = self.prev_head_addresses.lock().await;
            let has_graph_changes = match prev_addresses.get(&graph) {
                Some(prev_head) => prev_head != &current_head,
                None => true, // First time seeing this graph
            };

            if has_graph_changes {
                trace!(
                    ?graph,
                    ?current_head,
                    "graph head address changed, triggering hello notification broadcast"
                );
                // Update stored head address
                HashMap::insert(&mut prev_addresses, graph, current_head);
                drop(prev_addresses); // Release the lock before async call

                self.broadcast_hello_notifications(graph, current_head)
                    .await;
            } else {
                trace!(
                    ?graph,
                    "graph head address unchanged, no hello broadcast needed"
                );
            }
        }

        Ok(())
    }

    /// Gets the current graph head address using the proper Location->Segment->Command->Address flow.
    #[cfg(feature = "preview")]
    async fn get_graph_head_address(&self, graph_id: GraphId) -> Option<Address> {
        let client = &self.client;

        let mut aranya = client.lock_aranya().await;
        let storage = aranya.provider().get_storage(graph_id).ok()?;

        storage.get_head_address().ok()
    }

    /// Broadcasts hello notifications to subscribers when the graph changes.
    #[cfg(feature = "preview")]
    #[instrument(skip(self))]
    async fn broadcast_hello_notifications(&self, graph_id: GraphId, head: Address) {
        // TODO: Don't fire off a spawn here.
        let syncer = self.syncer.clone();
        drop(tokio::spawn(async move {
            if let Err(err) = syncer.broadcast_hello(graph_id, head).await {
                warn!(
                    error = %err.report(),
                    ?graph_id,
                    ?head,
                    "peers.broadcast_hello failed"
                );
            }
        }));
    }
}

/// The guts of [`Api`].
///
/// This is separated out so we only have to clone one [`Arc`]
/// (inside [`Api`]).
#[derive_where(Debug)]
struct ApiInner {
    client: Client,
    /// Local address of the API.
    local_addr: Addr,
    /// Public keys of current device.
    pk: std::sync::Mutex<PublicKeys<CS>>,
    /// Handle to talk with the syncer.
    syncer: SyncHandle,
    /// Handles graph effects from the syncer.
    #[derive_where(skip(Debug))]
    effect_handler: EffectHandler,
    #[cfg(feature = "afc")]
    afc: Arc<Afc<CE, CS, KS>>,
    teams: TeamConfigStore,
}

impl ApiInner {
    fn get_pk(&self) -> api::Result<PublicKeyBundle> {
        let pk = self.pk.lock().expect("poisoned");
        Ok(PublicKeyBundle::try_from(&*pk).context("bad key bundle")?)
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
    async fn check_team_valid(&self, team: api::TeamId) -> anyhow::Result<GraphId> {
        if !self.teams.contains(team) {
            anyhow::bail!("team {team} not created or added")
        }
        if self
            .client
            .invalid_graphs()
            .contains(GraphId::transmute(team))
        {
            // TODO: return custom daemon error type
            anyhow::bail!("team {team} invalid due to graph finalization error")
        }
        Ok(GraphId::transmute(team))
    }
}

impl DaemonApi for Api {
    //
    // Misc
    //

    #[instrument(skip(self), err)]
    async fn version(self, _: context::Context) -> api::Result<api::Version> {
        api::Version::parse(env!("CARGO_PKG_VERSION")).map_err(Into::into)
    }

    #[instrument(skip(self), err)]
    async fn aranya_local_addr(self, _: context::Context) -> api::Result<Addr> {
        Ok(self.local_addr)
    }

    #[instrument(skip(self), err)]
    async fn get_public_key_bundle(self, _: context::Context) -> api::Result<api::PublicKeyBundle> {
        Ok(self
            .get_pk()
            .context("unable to get device public keys")?
            .into())
    }

    #[instrument(skip(self), err)]
    async fn get_device_id(self, _: context::Context) -> api::Result<api::DeviceId> {
        self.device_id().map(api::DeviceId::transmute)
    }

    #[cfg(feature = "test-utils")]
    #[instrument(skip(self, ctx), err)]
    async fn test_trace_id(self, ctx: context::Context) -> api::Result<String> {
        let trace_id = ctx.trace_context.trace_id.to_string();
        info!(rpc.trace_id = %trace_id, "RPC: TestTraceId");
        Ok(trace_id)
    }

    #[cfg(feature = "afc")]
    #[instrument(skip(self), err)]
    async fn afc_shm_info(self, _: context::Context) -> api::Result<api::AfcShmInfo> {
        Ok(self.afc.get_shm_info().await)
    }

    //
    // Syncing
    //

    #[instrument(skip(self), err)]
    async fn add_sync_peer(
        self,
        _: context::Context,
        peer: Addr,
        team: api::TeamId,
        cfg: api::SyncPeerConfig,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;
        let peer = SyncPeer::new(peer, graph);
        self.syncer.add_peer(peer, cfg).await?;
        trace!(?graph, "added sync peer");
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
        let graph = self.check_team_valid(team).await?;
        let peer = SyncPeer::new(peer, graph);
        self.syncer.sync_now(peer, cfg).await?;
        trace!(?graph, "sync_now completed");
        Ok(())
    }

    #[cfg(feature = "preview")]
    #[instrument(skip(self), err)]
    async fn sync_hello_subscribe(
        self,
        _: context::Context,
        peer: Addr,
        team: api::TeamId,
        graph_change_debounce: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;
        let peer = SyncPeer::new(peer, graph);
        self.syncer
            .sync_hello_subscribe(peer, graph_change_debounce, duration, schedule_delay)
            .await?;
        trace!(?graph, "subscribed to sync hello");
        Ok(())
    }

    #[cfg(feature = "preview")]
    #[instrument(skip(self), err)]
    async fn sync_hello_unsubscribe(
        self,
        _: context::Context,
        peer: Addr,
        team: api::TeamId,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;
        let peer = SyncPeer::new(peer, graph);
        self.syncer.sync_hello_unsubscribe(peer).await?;
        trace!(?graph, "unsubscribed from sync hello");
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn remove_sync_peer(
        self,
        _: context::Context,
        peer: Addr,
        team: api::TeamId,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;
        let peer = SyncPeer::new(peer, graph);
        self.syncer
            .remove_peer(peer)
            .await
            .context("unable to remove sync peer")?;
        trace!(?graph, "removed sync peer");
        Ok(())
    }

    //
    // Local team management
    //

    #[instrument(skip(self), err)]
    async fn add_team(self, _: context::Context, cfg: api::AddTeamConfig) -> api::Result<()> {
        let team = cfg.team_id;

        if !self.teams.add(team) {
            return Err(anyhow!("team {team} is already present").into());
        }
        self.check_team_valid(team).await?;

        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn remove_team(self, _: context::Context, team: api::TeamId) -> api::Result<()> {
        if !self.teams.remove(team) {
            return Err(anyhow!("team {team} was not present").into());
        }

        self.syncer
            .remove_graph(GraphId::transmute(team))
            .await
            .context("unable to remove sync data for graph")?;

        self.client
            .lock_aranya()
            .await
            .remove_graph(GraphId::transmute(team))
            .context("unable to remove graph from storage")?;

        trace!(graph = ?GraphId::transmute(team), "removed team");
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn create_team(
        self,
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

        if !self.teams.add(team_id) {
            return Err(
                anyhow!("new team {team_id} with random nonce should not be present").into(),
            );
        }

        Ok(team_id)
    }

    #[instrument(skip(self), err)]
    async fn close_team(self, _: context::Context, team: api::TeamId) -> api::Result<()> {
        let _graph = self.check_team_valid(team).await?;

        todo!();
    }

    //
    // Device onboarding
    //

    #[instrument(skip(self), err)]
    async fn add_device_to_team(
        self,
        _: context::Context,
        team: api::TeamId,
        keys: api::PublicKeyBundle,
        initial_role: Option<api::RoleId>,
        rank: api::Rank,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .add_device(keys.into(), initial_role.map(RoleId::transmute), rank)
            .await
            .context("unable to add device to team")?;
        self.effect_handler.handle_effects(graph, &effects).await?;
        trace!(?graph, "added device to team");
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn remove_device_from_team(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .remove_device(DeviceId::transmute(device))
            .await
            .context("unable to remove device from team")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        trace!(?graph, "removed device from team");
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn devices_on_team(
        self,
        _: context::Context,
        team: api::TeamId,
    ) -> api::Result<Box<[api::DeviceId]>> {
        let graph = self.check_team_valid(team).await?;

        let devices = self
            .client
            .actions(graph)
            .query_devices_on_team()
            .await
            .context("unable to query devices on team")?
            .into_iter()
            .filter_map(|e| {
                if let Effect::QueryDevicesOnTeamResult(e) = e {
                    Some(api::DeviceId::from_base(e.device_id))
                } else {
                    warn!(name = e.name(), "unexpected effect");
                    None
                }
            })
            .collect();

        trace!(?graph, "queried devices on team");
        Ok(devices)
    }

    #[instrument(skip(self), err)]
    async fn device_public_key_bundle(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<api::PublicKeyBundle> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .query_device_public_key_bundle(DeviceId::transmute(device))
            .await
            .context("unable to query device public key bundle")?;
        if let Some(Effect::QueryDeviceKeyBundleResult(e)) =
            find_effect!(effects, Effect::QueryDeviceKeyBundleResult(_e))
        {
            trace!(?graph, "queried device public key bundle");
            Ok(api::PublicKeyBundle::from(e.device_keys))
        } else {
            Err(api::Error::DoesNotExist(
                "device public key bundle not found".into(),
            ))
        }
    }

    #[instrument(skip(self), err)]
    async fn labels_assigned_to_device(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<Box<[api::Label]>> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .query_labels_assigned_to_device(DeviceId::transmute(device))
            .await
            .context("unable to query device label assignments")?;
        let mut labels = Vec::new();
        for e in effects {
            if let Effect::QueryLabelsAssignedToDeviceResult(e) = e {
                debug!("found label: {}", e.label_id);
                labels.push(api::Label {
                    id: api::LabelId::from_base(e.label_id),
                    name: e.label_name,
                    author_id: api::DeviceId::from_base(e.label_author_id),
                });
            }
        }
        trace!(?graph, "queried labels assigned to device");
        return Ok(labels.into_boxed_slice());
    }

    #[instrument(skip(self), err)]
    async fn device_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
    ) -> api::Result<Option<api::Role>> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .query_device_role(DeviceId::transmute(device))
            .await
            .context("unable to query device role")?;
        if let Some(Effect::QueryDeviceRoleResult(e)) =
            find_effect!(&effects, Effect::QueryDeviceRoleResult(_))
        {
            trace!(?graph, "queried device role");
            Ok(Some(api::Role {
                id: api::RoleId::from_base(e.role_id),
                name: e.name.clone(),
                author_id: api::DeviceId::from_base(e.author_id),
                default: e.default,
            }))
        } else {
            trace!(?graph, "queried device role (none)");
            Ok(None)
        }
    }

    #[instrument(skip(self), err)]
    async fn create_role(
        self,
        _: context::Context,
        team: api::TeamId,
        role_name: Text,
        rank: api::Rank,
    ) -> api::Result<api::Role> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .create_role(role_name, rank)
            .await
            .context("unable to create role")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        if let Some(Effect::RoleCreated(e)) = find_effect!(&effects, Effect::RoleCreated(_)) {
            trace!(?graph, "created role");
            Ok(api::Role {
                id: api::RoleId::from_base(e.role_id),
                name: e.name.clone(),
                author_id: api::DeviceId::from_base(e.author_id),
                default: e.default,
            })
        } else {
            Err(anyhow!("wrong effect when creating role").into())
        }
    }

    #[instrument(skip(self), err)]
    async fn delete_role(
        self,
        _: context::Context,
        team: api::TeamId,
        role_id: api::RoleId,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .delete_role(RoleId::transmute(role_id))
            .await
            .context("unable to delete role")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        if let Some(Effect::RoleDeleted(e)) = find_effect!(&effects, Effect::RoleDeleted(_)) {
            info!("Deleted role {role_id} ({})", e.name());
            trace!(?graph, "deleted role");
            Ok(())
        } else {
            Err(anyhow!("wrong effect when creating role").into())
        }
    }

    #[instrument(skip(self), err)]
    async fn assign_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        role: api::RoleId,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .assign_role(DeviceId::transmute(device), RoleId::transmute(role))
            .await
            .context("unable to assign role")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        if let Some(Effect::RoleAssigned(_e)) = find_effect!(&effects, Effect::RoleAssigned(_e)) {
            trace!(?device, ?role, "assigned role to device");
            Ok(())
        } else {
            Err(anyhow!("unable to assign role").into())
        }
    }

    #[instrument(skip(self), err)]
    async fn revoke_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        role: api::RoleId,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .revoke_role(DeviceId::transmute(device), RoleId::transmute(role))
            .await
            .context("unable to revoke device role")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        if let Some(Effect::RoleRevoked(_e)) = find_effect!(&effects, Effect::RoleRevoked(_e)) {
            trace!(?device, ?role, "revoked role from device");
            Ok(())
        } else {
            Err(anyhow!("unable to revoke device role").into())
        }
    }

    #[instrument(skip(self), err)]
    async fn change_role(
        self,
        _: context::Context,
        team: api::TeamId,
        device_id: api::DeviceId,
        old_role_id: api::RoleId,
        new_role_id: api::RoleId,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .change_role(
                DeviceId::transmute(device_id),
                RoleId::transmute(old_role_id),
                RoleId::transmute(new_role_id),
            )
            .await
            .context("unable to change device role")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        if let Some(Effect::RoleChanged(_e)) = find_effect!(&effects, Effect::RoleChanged(_e)) {
            trace!(?graph, "changed role");
            Ok(())
        } else {
            Err(anyhow!("unable to change device role").into())
        }
    }

    #[cfg(feature = "afc")]
    #[instrument(skip(self), err)]
    async fn create_afc_channel(
        self,
        _: context::Context,
        team: api::TeamId,
        peer_id: api::DeviceId,
        label: api::LabelId,
    ) -> api::Result<api::AfcSendChannelInfo> {
        let graph = self.check_team_valid(team).await?;

        info!("creating afc uni channel");

        let SessionData { ctrl, effects } = self
            .client
            .actions(graph)
            .create_afc_uni_channel_off_graph(
                DeviceId::transmute(peer_id),
                LabelId::transmute(label),
            )
            .await?;

        let [Effect::AfcUniChannelCreated(e)] = effects.as_slice() else {
            bug!("expected afc uni channel created effect")
        };

        self.effect_handler.handle_effects(graph, &effects).await?;

        let (local_channel_id, channel_id) = self.afc.uni_channel_created(e).await?;
        info!("afc uni channel created");

        let ctrl = get_afc_ctrl(ctrl)?;

        Ok(api::AfcSendChannelInfo {
            ctrl,
            local_channel_id,
            channel_id,
        })
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
    async fn accept_afc_channel(
        self,
        _: context::Context,
        team: api::TeamId,
        ctrl: api::AfcCtrl,
    ) -> api::Result<api::AfcReceiveChannelInfo> {
        let graph = self.check_team_valid(team).await?;

        let mut session = self.client.session_new(graph).await?;

        let effects = self.client.session_receive(&mut session, &ctrl).await?;

        let [Effect::AfcUniChannelReceived(e)] = effects.as_slice() else {
            bug!("expected afc uni channel received effect")
        };

        self.effect_handler.handle_effects(graph, &effects).await?;

        let (local_channel_id, channel_id) = self.afc.uni_channel_received(e).await?;
        trace!(?graph, "accepted afc channel");

        return Ok(api::AfcReceiveChannelInfo {
            local_channel_id,
            channel_id,
            label_id: api::LabelId::from_base(e.label_id),
            peer_id: api::DeviceId::from_base(e.sender_id),
        });
    }

    #[instrument(skip(self), err)]
    async fn create_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label_name: Text,
        rank: api::Rank,
    ) -> api::Result<api::LabelId> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .create_label(label_name.clone(), rank)
            .await
            .context("unable to create label")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        if let Some(Effect::LabelCreated(e)) = find_effect!(&effects, Effect::LabelCreated(_e)) {
            trace!(label = %label_name, "created label");
            Ok(api::LabelId::from_base(e.label_id))
        } else {
            Err(anyhow!("unable to create label").into())
        }
    }

    #[instrument(skip(self), err)]
    async fn delete_label(
        self,
        _: context::Context,
        team: api::TeamId,
        label_id: api::LabelId,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .delete_label(LabelId::transmute(label_id))
            .await
            .context("unable to delete label")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        if let Some(Effect::LabelDeleted(_e)) = find_effect!(&effects, Effect::LabelDeleted(_e)) {
            trace!(?label_id, "deleted label");
            Ok(())
        } else {
            Err(anyhow!("unable to delete label").into())
        }
    }

    #[instrument(skip(self), err)]
    async fn assign_label_to_device(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label_id: api::LabelId,
        op: api::ChanOp,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .assign_label_to_device(
                DeviceId::transmute(device),
                LabelId::transmute(label_id),
                op.into(),
            )
            .await
            .context("unable to assign label")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        if let Some(Effect::AssignedLabelToDevice(_e)) =
            find_effect!(&effects, Effect::AssignedLabelToDevice(_e))
        {
            trace!(?device, ?label_id, "assigned label to device");
            Ok(())
        } else {
            Err(anyhow!("unable to assign label").into())
        }
    }

    #[instrument(skip(self), err)]
    async fn revoke_label_from_device(
        self,
        _: context::Context,
        team: api::TeamId,
        device: api::DeviceId,
        label_id: api::LabelId,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .revoke_label_from_device(DeviceId::transmute(device), LabelId::transmute(label_id))
            .await
            .context("unable to revoke label")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        if let Some(Effect::LabelRevokedFromDevice(_e)) =
            find_effect!(&effects, Effect::LabelRevokedFromDevice(_e))
        {
            trace!(?device, ?label_id, "revoked label from device");
            Ok(())
        } else {
            Err(anyhow!("unable to revoke label").into())
        }
    }

    #[instrument(skip(self), err)]
    async fn label(
        self,
        _: context::Context,
        team: api::TeamId,
        label_id: api::LabelId,
    ) -> api::Result<api::Label> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .query_label(LabelId::transmute(label_id))
            .await
            .context("unable to query label")?;
        if let Some(Effect::QueryLabelResult(e)) =
            find_effect!(&effects, Effect::QueryLabelResult(_e))
        {
            trace!(?graph, "queried label");
            Ok(api::Label {
                id: api::LabelId::from_base(e.label_id),
                name: e.label_name.clone(),
                author_id: api::DeviceId::from_base(e.label_author_id),
            })
        } else {
            trace!(?graph, "queried label (not found)");
            Err(api::Error::DoesNotExist("label not found".into()))
        }
    }

    #[instrument(skip(self), err)]
    async fn labels(self, _: context::Context, team: api::TeamId) -> api::Result<Vec<api::Label>> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .query_labels()
            .await
            .context("unable to query labels")?;
        let mut labels: Vec<api::Label> = Vec::new();
        for e in effects {
            if let Effect::QueryLabelsResult(e) = e {
                debug!("found label: {}", e.label_id);
                labels.push(api::Label {
                    id: api::LabelId::from_base(e.label_id),
                    name: e.label_name.clone(),
                    author_id: api::DeviceId::from_base(e.label_author_id),
                });
            }
        }
        trace!(?graph, "queried labels");
        Ok(labels)
    }

    #[instrument(skip(self), err)]
    async fn setup_default_roles(
        self,
        _: context::Context,
        team: api::TeamId,
    ) -> api::Result<Box<[api::Role]>> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .setup_default_roles()
            .await
            .context("unable to setup default roles")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        let roles = effects
            .into_iter()
            .filter_map(|e| {
                if let Effect::RoleCreated(e @ RoleCreated { default: true, .. }) = e {
                    Some(api::Role {
                        id: api::RoleId::from_base(e.role_id),
                        name: e.name,
                        author_id: api::DeviceId::from_base(e.author_id),
                        default: e.default,
                    })
                } else {
                    warn!(name = e.name(), "unexpected effect");
                    None
                }
            })
            .collect();

        trace!(?graph, "setup default roles");
        Ok(roles)
    }

    #[instrument(skip(self), err)]
    async fn team_roles(
        self,
        _: context::Context,
        team: api::TeamId,
    ) -> api::Result<Box<[api::Role]>> {
        let graph = self.check_team_valid(team).await?;

        let roles = self
            .client
            .actions(graph)
            .query_team_roles()
            .await
            .context("unable to query team roles")?
            .into_iter()
            .filter_map(|e| {
                if let Effect::QueryTeamRolesResult(e) = e {
                    Some(api::Role {
                        id: api::RoleId::from_base(e.role_id),
                        name: e.name,
                        author_id: api::DeviceId::from_base(e.author_id),
                        default: e.default,
                    })
                } else {
                    warn!(name = e.name(), "unexpected effect");
                    None
                }
            })
            .collect();
        trace!(?graph, "queried team roles");
        Ok(roles)
    }

    //
    // Role management
    //

    #[instrument(skip(self), err)]
    async fn add_perm_to_role(
        self,
        _: context::Context,
        team: api::TeamId,
        role: api::RoleId,
        perm: api::Perm,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .add_perm_to_role(RoleId::transmute(role), perm.into())
            .await
            .context("unable to add permission to role")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        trace!(?graph, "added permission to role");
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn remove_perm_from_role(
        self,
        _: context::Context,
        team: api::TeamId,
        role: api::RoleId,
        perm: api::Perm,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .remove_perm_from_role(RoleId::transmute(role), perm.into())
            .await
            .context("unable to add permission to role")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        trace!(?graph, "removed permission from role");
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn query_role_perms(
        self,
        _: context::Context,
        team: api::TeamId,
        role: api::RoleId,
    ) -> api::Result<Vec<api::Perm>> {
        let graph = self.check_team_valid(team).await?;

        let perms = self
            .client
            .actions(graph)
            .query_role_perms(RoleId::transmute(role))
            .await
            .context("unable to query role permissions")?
            .into_iter()
            .filter_map(|e| {
                if let Effect::QueryRolePermsResult(e) = e {
                    Some(e.perm.into())
                } else {
                    warn!(name = e.name(), "unexpected effect");
                    None
                }
            })
            .collect();

        trace!(?graph, "queried role permissions");
        Ok(perms)
    }

    #[instrument(skip(self), err)]
    async fn change_rank(
        self,
        _: context::Context,
        team: api::TeamId,
        object_id: api::ObjectId,
        old_rank: api::Rank,
        new_rank: api::Rank,
    ) -> api::Result<()> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .change_rank(object_id, old_rank, new_rank)
            .await
            .context("unable to change rank")?;
        self.effect_handler.handle_effects(graph, &effects).await?;

        if find_effect!(&effects, Effect::RankChanged(_)).is_some() {
            trace!(?graph, "changed rank");
            Ok(())
        } else {
            Err(anyhow!("unable to change rank").into())
        }
    }

    #[instrument(skip(self), err)]
    async fn query_rank(
        self,
        _: context::Context,
        team: api::TeamId,
        object_id: api::ObjectId,
    ) -> api::Result<api::Rank> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .query_rank(object_id)
            .await
            .context("unable to query rank")?;

        if let Some(Effect::QueryRankResult(e)) = find_effect!(&effects, Effect::QueryRankResult(_))
        {
            trace!(?graph, "queried rank");
            Ok(api::Rank::new(e.rank))
        } else {
            Err(api::Error::DoesNotExist("rank not found for object".into()))
        }
    }

    #[cfg(feature = "test-utils")]
    #[instrument(skip(self), err)]
    async fn query_device_generation(
        self,
        _: context::Context,
        team: api::TeamId,
        device_id: api::DeviceId,
    ) -> api::Result<Option<i64>> {
        let graph = self.check_team_valid(team).await?;

        let effects = self
            .client
            .actions(graph)
            .query_device_generation(DeviceId::transmute(device_id))
            .await
            .context("unable to query device generation")?;

        if let Some(Effect::QueryDeviceGenerationResult(e)) =
            find_effect!(&effects, Effect::QueryDeviceGenerationResult(_))
        {
            trace!(?graph, "queried device generation");
            Ok(Some(e.generation))
        } else {
            Ok(None)
        }
    }
}

impl From<api::PublicKeyBundle> for PublicKeyBundle {
    fn from(value: api::PublicKeyBundle) -> Self {
        PublicKeyBundle {
            ident_key: value.identity,
            sign_key: value.signing,
            enc_key: value.encryption,
        }
    }
}

impl From<PublicKeyBundle> for api::PublicKeyBundle {
    fn from(value: PublicKeyBundle) -> Self {
        api::PublicKeyBundle {
            identity: value.ident_key,
            signing: value.sign_key,
            encryption: value.enc_key,
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

#[allow(clippy::disallowed_macros)] // `From` is infallible so we cannot use `bug!`
impl From<api::Perm> for Perm {
    fn from(value: api::Perm) -> Self {
        match value {
            api::Perm::AddDevice => Perm::AddDevice,
            api::Perm::RemoveDevice => Perm::RemoveDevice,
            api::Perm::TerminateTeam => Perm::TerminateTeam,
            api::Perm::ChangeRank => Perm::ChangeRank,
            api::Perm::CreateRole => Perm::CreateRole,
            api::Perm::DeleteRole => Perm::DeleteRole,
            api::Perm::AssignRole => Perm::AssignRole,
            api::Perm::RevokeRole => Perm::RevokeRole,
            api::Perm::ChangeRolePerms => Perm::ChangeRolePerms,
            api::Perm::SetupDefaultRole => Perm::SetupDefaultRole,
            api::Perm::CreateLabel => Perm::CreateLabel,
            api::Perm::DeleteLabel => Perm::DeleteLabel,
            api::Perm::AssignLabel => Perm::AssignLabel,
            api::Perm::RevokeLabel => Perm::RevokeLabel,
            api::Perm::CanUseAfc => Perm::CanUseAfc,
            api::Perm::CreateAfcUniChannel => Perm::CreateAfcUniChannel,
            _ => unreachable!("daemon Perm enum is out of sync with aranya_daemon_api::Perm"),
        }
    }
}

impl From<Perm> for api::Perm {
    fn from(value: Perm) -> Self {
        match value {
            Perm::AddDevice => api::Perm::AddDevice,
            Perm::RemoveDevice => api::Perm::RemoveDevice,
            Perm::TerminateTeam => api::Perm::TerminateTeam,
            Perm::ChangeRank => api::Perm::ChangeRank,
            Perm::CreateRole => api::Perm::CreateRole,
            Perm::DeleteRole => api::Perm::DeleteRole,
            Perm::AssignRole => api::Perm::AssignRole,
            Perm::RevokeRole => api::Perm::RevokeRole,
            Perm::ChangeRolePerms => api::Perm::ChangeRolePerms,
            Perm::SetupDefaultRole => api::Perm::SetupDefaultRole,
            Perm::CreateLabel => api::Perm::CreateLabel,
            Perm::DeleteLabel => api::Perm::DeleteLabel,
            Perm::AssignLabel => api::Perm::AssignLabel,
            Perm::RevokeLabel => api::Perm::RevokeLabel,
            Perm::CanUseAfc => api::Perm::CanUseAfc,
            Perm::CreateAfcUniChannel => api::Perm::CreateAfcUniChannel,
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
