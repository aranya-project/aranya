//! Test module for aranya-daemon.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    rust_2018_idioms
)]

use std::{
    collections::HashMap,
    fs,
    net::Ipv4Addr,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use aranya_crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    keystore::fs_keystore::Store,
    policy::{LabelId, RoleId},
    Csprng, DeviceId, Rng,
};
use aranya_daemon_api::{text, TeamId};
use aranya_keygen::{PublicKeyBundle, PublicKeys};
use aranya_runtime::{
    storage::linear::{libc::FileManager, LinearStorageProvider},
    ClientError, ClientState, GraphId,
};
use aranya_util::{ready, Addr};
use s2n_quic::provider::tls::rustls::rustls::crypto::PresharedKey;
use serial_test::serial;
use tempfile::{tempdir, TempDir};
use test_log::test;
use tokio::{
    sync::mpsc::{self, Receiver},
    task::{self, AbortHandle},
};

use crate::{
    actions::Actions,
    aranya,
    policy::{Effect, Perm, PublicKeyBundle as DeviceKeyBundle},
    sync::{self, quic::PskStore, SyncPeer},
    vm_policy::{PolicyEngine, POLICY_SOURCE},
    AranyaStore,
};

/// Queries the rank of an object via the policy engine, returning the raw i64 value.
async fn query_rank(device: &TestDevice, object_id: aranya_daemon_api::ObjectId) -> Result<i64> {
    let effects = device.actions().query_rank(object_id).await?;
    effects
        .into_iter()
        .find_map(|e| match e {
            Effect::QueryRankResult(r) => Some(r.rank),
            _ => None,
        })
        .context("expected QueryRankResult effect")
}

// Aranya graph client for testing.
type TestClient =
    aranya::Client<PolicyEngine<DefaultEngine, Store>, LinearStorageProvider<FileManager>>;

type TestState = sync::quic::QuicState;
// Aranya sync client for testing.
type TestSyncer = sync::SyncManager<TestState, crate::PS, crate::SP, crate::EF>;

// Aranya sync server for testing.
type TestServer = sync::quic::Server<crate::PS, crate::SP>;

struct TestDevice {
    /// Aranya sync client.
    syncer: TestSyncer,
    /// The Aranya graph ID.
    graph_id: GraphId,
    /// The address that the sync server is listening on.
    sync_local_addr: Addr,
    /// Aborts the server task.
    handle: AbortHandle,
    /// Public keys
    pk: PublicKeys<DefaultCipherSuite>,
    effect_recv: Receiver<(GraphId, Vec<Effect>)>,
}

impl TestDevice {
    pub fn new(
        server: TestServer,
        pk: PublicKeys<DefaultCipherSuite>,
        graph_id: GraphId,
        syncer: TestSyncer,
        effect_recv: Receiver<(GraphId, Vec<crate::EF>)>,
    ) -> Result<Self> {
        let waiter = ready::Waiter::new(1);
        let notifier = waiter.notifier();
        let sync_local_addr = server.local_addr().into();
        let handle = task::spawn(async { server.serve(notifier).await }).abort_handle();
        // let (send_effects, effect_recv) = mpsc::channel(1);
        Ok(Self {
            syncer,
            graph_id,
            sync_local_addr,
            handle,
            pk,
            effect_recv,
        })
    }
}

impl TestDevice {
    /// Syncs with a device and expects a certain number of commands to be received.
    ///
    /// Returns the effects that were received.
    pub async fn sync_expect(
        &mut self,
        device: &TestDevice,
        must_receive: Option<usize>,
    ) -> Result<Vec<Effect>> {
        let cmd_count = self
            .syncer
            .sync(SyncPeer::new(device.sync_local_addr, self.graph_id))
            .await
            .with_context(|| format!("unable to sync with peer at {}", device.sync_local_addr))?;
        if let Some(must_receive) = must_receive {
            assert_eq!(cmd_count, must_receive);
        }

        while let Some((graph_id, effects)) = self.effect_recv.recv().await {
            if graph_id == self.graph_id {
                return Ok(effects);
            }
        }
        bail!("Channel closed or nothing to receive")
    }

    pub fn actions(
        &self,
    ) -> impl Actions<
        PolicyEngine<DefaultEngine<Rng>, Store>,
        LinearStorageProvider<FileManager>,
        DefaultEngine<Rng>,
    > {
        self.syncer.client().actions(self.graph_id)
    }
}

impl Drop for TestDevice {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl Deref for TestDevice {
    type Target = TestClient;

    fn deref(&self) -> &Self::Target {
        self.syncer.client()
    }
}

impl DerefMut for TestDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.syncer.client_mut()
    }
}

struct TestTeam<'a> {
    owner: &'a mut TestDevice,
    admin: &'a mut TestDevice,
    operator: &'a mut TestDevice,
    membera: &'a mut TestDevice,
    memberb: &'a mut TestDevice,
}

impl<'a> TestTeam<'a> {
    pub fn new(clients: &'a mut [TestDevice]) -> Self {
        assert!(clients.len() >= 5);
        let [owner, admin, operator, membera, memberb, ..] = clients else {
            panic!("need at least 5 clients");
        };

        TestTeam {
            owner,
            admin,
            operator,
            membera,
            memberb,
        }
    }
}

struct TestCtx {
    /// The working directory for the test.
    dir: TempDir,
    // Per-client ID.
    // Incrementing counter is used to differentiate clients for test purposes.
    id: u64,
}

impl TestCtx {
    /// Creates a new test context.
    pub fn new() -> Result<Self> {
        Ok(Self {
            dir: tempdir()?,
            id: 0,
        })
    }

    /// Creates a single client.
    pub async fn new_client(
        &mut self,
        name: &str,
        id: GraphId,
    ) -> Result<(TestDevice, Arc<PskStore>)> {
        let root = self.dir.path().join(name);
        assert!(!root.try_exists()?, "duplicate client name: {name}");

        let (syncer, server, pk, psk_store, effects_recv) = {
            let mut store = {
                let path = root.join("keystore");
                fs::create_dir_all(&path)?;
                Store::open(path).map(AranyaStore::new)?
            };
            let (eng, _) = DefaultEngine::<Rng>::from_entropy(Rng);
            let bundle = PublicKeyBundle::generate(&eng, &mut store)
                .context("unable to generate `PublicKeyBundle`")?;

            let storage_dir = root.join("storage");
            fs::create_dir_all(&storage_dir)?;

            let pk = bundle.public_keys(&eng, &store)?;

            let client = aranya::Client::new(ClientState::new(
                PolicyEngine::new(
                    POLICY_SOURCE,
                    eng,
                    store.try_clone().context("unable to clone keystore")?,
                    bundle.device_id,
                )?,
                LinearStorageProvider::new(FileManager::new(&storage_dir)?),
            ));

            let any_local_addr = Addr::from((Ipv4Addr::LOCALHOST, 0));
            let psk_store = PskStore::new([]);
            let psk_store = Arc::new(psk_store);

            let (send_effects, effects_recv) = mpsc::channel(1);

            // Create server first to get the actual listening address
            let (server, _sync_peers, conn_map, syncer_recv) =
                TestServer::new(client.clone(), &any_local_addr, psk_store.clone()).await?;

            // Create syncer with the actual server address
            let syncer = TestSyncer::new(
                client.clone(),
                send_effects,
                psk_store.clone(),
                (server.local_addr().into(), any_local_addr),
                syncer_recv,
                conn_map,
            )?;

            (syncer, server, pk, psk_store, effects_recv)
        };

        Ok((
            TestDevice::new(server, pk, id, syncer, effects_recv)?,
            psk_store,
        ))
    }

    /// Creates `n` members.
    pub async fn new_group(&mut self, n: usize) -> Result<Vec<TestDevice>> {
        let test_psk = PresharedKey::external(b"test-identity", b"test-secret-key-32-bytes-long!!")
            .context("failed to create test PSK")?
            .with_hash_alg(
                s2n_quic::provider::tls::rustls::rustls::crypto::hash::HashAlgorithm::SHA384,
            )
            .context("failed to set hash algorithm")?;
        let mut stores = Vec::<Arc<PskStore>>::new();
        let mut clients = Vec::<TestDevice>::new();
        for i in 0..n {
            let name = format!("client_{}", self.id);
            self.id += 1;

            let id = if i == 0 {
                GraphId::default()
            } else {
                clients[0].graph_id
            };
            let (mut client, psk_store) = self
                .new_client(&name, id)
                .await
                .with_context(|| format!("unable to create client {name}"))?;
            stores.push(psk_store);
            // Eww, gross.
            if id == GraphId::default() {
                let nonce = &mut [0u8; 16];
                Rng.fill_bytes(nonce);
                (client.graph_id, _) = client
                    .create_team(DeviceKeyBundle::try_from(&client.pk)?, Some(nonce))
                    .await?;
            }
            clients.push(client)
        }
        for store in stores {
            let team_id = TeamId::from(*clients[0].graph_id.as_array());
            store.insert(team_id, Arc::new(test_psk.clone()));
            store.set_team(team_id);
        }
        Ok(clients)
    }

    /// Creates default team.
    pub async fn new_team(&mut self) -> Result<Vec<TestDevice>> {
        let mut clients = self
            .new_group(5)
            .await
            .context("unable to create clients")?;
        let team = TestTeam::new(&mut clients);
        let owner = team.owner;
        let admin = team.admin;
        let operator = team.operator;
        let membera = team.membera;
        let memberb = team.memberb;

        // team setup - first setup default roles
        // Get owner role ID from existing roles
        let role_effects = owner.actions().query_team_roles().await?;
        let roles: Vec<_> = role_effects
            .into_iter()
            .filter_map(|e| {
                if let Effect::QueryTeamRolesResult(result) = e {
                    Some(aranya_daemon_api::Role {
                        id: aranya_daemon_api::RoleId::from_base(result.role_id),
                        name: result.name,
                        author_id: aranya_daemon_api::DeviceId::from_base(result.author_id),
                        default: result.default,
                    })
                } else {
                    None
                }
            })
            .collect();
        roles
            .into_iter()
            .find(|role| role.name.as_str() == "owner" && role.default)
            .context("owner role not found")?;

        // Setup default roles (admin, operator, member)
        owner
            .actions()
            .setup_default_roles()
            .await
            .context("unable to setup default roles")?;

        // Now get the role IDs for admin and operator
        let all_role_effects = owner.actions().query_team_roles().await?;
        let all_roles: Vec<_> = all_role_effects
            .into_iter()
            .filter_map(|e| {
                if let Effect::QueryTeamRolesResult(result) = e {
                    Some(aranya_daemon_api::Role {
                        id: aranya_daemon_api::RoleId::from_base(result.role_id),
                        name: result.name,
                        author_id: aranya_daemon_api::DeviceId::from_base(result.author_id),
                        default: result.default,
                    })
                } else {
                    None
                }
            })
            .collect();
        let admin_role = all_roles
            .iter()
            .find(|role| role.name.as_str() == "admin" && role.default)
            .context("admin role not found after setup")?;
        let operator_role = all_roles
            .iter()
            .find(|role| role.name.as_str() == "operator" && role.default)
            .context("operator role not found after setup")?;
        let member_role = all_roles
            .iter()
            .find(|role| role.name.as_str() == "member" && role.default)
            .context("member role not found after setup")?;

        let admin_role_rank =
            query_rank(owner, aranya_daemon_api::ObjectId::transmute(admin_role.id)).await?;
        owner
            .actions()
            .add_device_with_rank(
                DeviceKeyBundle::try_from(&admin.pk)?,
                None,
                (admin_role_rank.saturating_sub(1)).into(),
            )
            .await
            .context("unable to add admin member")?;
        owner
            .actions()
            .assign_role(admin.pk.ident_pk.id()?, RoleId::transmute(admin_role.id))
            .await
            .context("unable to elevate admin role")?;
        admin.sync_expect(owner, None).await?;

        let admin_caches = admin.syncer.get_peer_caches();
        let owner_key = SyncPeer::new(owner.sync_local_addr, admin.graph_id);
        let admin_cache_size = admin_caches
            .lock()
            .await
            .get(&owner_key)
            .unwrap()
            .heads()
            .len();
        assert!(admin_cache_size > 0);

        let operator_role_rank = query_rank(
            owner,
            aranya_daemon_api::ObjectId::transmute(operator_role.id),
        )
        .await?;
        owner
            .actions()
            .add_device_with_rank(
                DeviceKeyBundle::try_from(&operator.pk)?,
                None,
                (operator_role_rank.saturating_sub(1)).into(),
            )
            .await
            .context("unable to add operator member")?;
        owner
            .actions()
            .assign_role(
                operator.pk.ident_pk.id()?,
                RoleId::transmute(operator_role.id),
            )
            .await
            .context("unable to elevate operator role")?;
        operator.sync_expect(owner, None).await?;

        let operator_caches = operator.syncer.get_peer_caches();
        let operator_cache_size = operator_caches
            .lock()
            .await
            .get(&owner_key)
            .unwrap()
            .heads()
            .len();
        assert!(operator_cache_size > 0);

        let member_role_rank = query_rank(
            owner,
            aranya_daemon_api::ObjectId::transmute(member_role.id),
        )
        .await?;
        admin
            .actions()
            .add_device_with_rank(
                DeviceKeyBundle::try_from(&membera.pk)?,
                None,
                (member_role_rank.saturating_sub(1)).into(),
            )
            .await
            .context("unable to add membera member")?;
        membera.sync_expect(admin, None).await?;
        admin
            .actions()
            .add_device_with_rank(
                DeviceKeyBundle::try_from(&memberb.pk)?,
                None,
                (member_role_rank.saturating_sub(1)).into(),
            )
            .await
            .context("unable to add memberb member")?;
        memberb.sync_expect(admin, None).await?;

        operator.sync_expect(admin, None).await?;
        owner.sync_expect(admin, None).await?;

        owner.sync_expect(operator, None).await?;
        admin.sync_expect(operator, None).await?;
        membera.sync_expect(operator, None).await?;
        memberb.sync_expect(operator, None).await?;

        Ok(clients)
    }
}

/// Tests creating a team.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_create_team() -> Result<()> {
    let mut ctx = TestCtx::new()?;

    ctx.new_team().await.context("unable to create team")?;
    Ok(())
}

/// Verifies default roles are seeded with their documented simple permissions.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_default_roles_seed_expected_permissions() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let admin_role = role_id_by_name(&roles, "admin");
    let operator_role = role_id_by_name(&roles, "operator");
    let member_role = role_id_by_name(&roles, "member");

    for (role, perm, message) in [
        (
            admin_role,
            Perm::AddDevice,
            "admin should already grant AddDevice",
        ),
        (
            admin_role,
            Perm::RemoveDevice,
            "admin should already grant RemoveDevice",
        ),
        (
            admin_role,
            Perm::CreateLabel,
            "admin should already grant CreateLabel",
        ),
        (
            admin_role,
            Perm::DeleteLabel,
            "admin should already grant DeleteLabel",
        ),
        (
            admin_role,
            Perm::ChangeRank,
            "admin should already grant ChangeRank",
        ),
        (
            admin_role,
            Perm::CreateRole,
            "admin should already grant CreateRole",
        ),
        (
            admin_role,
            Perm::DeleteRole,
            "admin should already grant DeleteRole",
        ),
        (
            admin_role,
            Perm::ChangeRolePerms,
            "admin should already grant ChangeRolePerms",
        ),
        (
            operator_role,
            Perm::AssignLabel,
            "operator should already grant AssignLabel",
        ),
        (
            operator_role,
            Perm::RevokeLabel,
            "operator should already grant RevokeLabel",
        ),
        (
            operator_role,
            Perm::AssignRole,
            "operator should already grant AssignRole",
        ),
        (
            operator_role,
            Perm::RevokeRole,
            "operator should already grant RevokeRole",
        ),
        (
            member_role,
            Perm::CanUseAfc,
            "member should already grant CanUseAfc",
        ),
        (
            member_role,
            Perm::CreateAfcUniChannel,
            "member should already grant CreateAfcUniChannel",
        ),
    ] {
        let err = owner
            .actions()
            .add_perm_to_role(role, perm)
            .await
            .expect_err(message);
        expect_not_authorized(err);
    }

    Ok(())
}

async fn load_default_roles(owner: &mut TestDevice) -> Result<HashMap<String, RoleId>> {
    let effects = owner.actions().query_team_roles().await?;
    let mut roles = HashMap::new();
    for effect in effects {
        if let Effect::QueryTeamRolesResult(result) = effect {
            roles.insert(result.name.to_string(), RoleId::from_base(result.role_id));
        }
    }
    Ok(roles)
}

fn role_id_by_name(roles: &HashMap<String, RoleId>, name: &str) -> RoleId {
    roles
        .get(name)
        .copied()
        .unwrap_or_else(|| panic!("expected role named {name}"))
}

fn device_id(device: &TestDevice) -> Result<DeviceId> {
    Ok(device.pk.ident_pk.id()?)
}

fn expect_not_authorized(err: anyhow::Error) {
    let err = err
        .downcast::<ClientError>()
        .expect("error should downcast to ClientError");
    assert!(
        matches!(err, ClientError::NotAuthorized),
        "unexpected error: {err}"
    );
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_add_device_requires_unique_id() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let (extra, _extra_store) = ctx
        .new_client("extra", owner.graph_id)
        .await
        .context("unable to create extra device")?;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let member_role_rank =
        query_rank(owner, aranya_daemon_api::ObjectId::transmute(member_role)).await?;

    owner
        .actions()
        .add_device_with_rank(
            DeviceKeyBundle::try_from(&extra.pk)?,
            None,
            (member_role_rank.saturating_sub(1)).into(),
        )
        .await
        .context("initial add should succeed")?;

    let err = owner
        .actions()
        .add_device_with_rank(
            DeviceKeyBundle::try_from(&extra.pk)?,
            None,
            (member_role_rank.saturating_sub(1)).into(),
        )
        .await
        .expect_err("expected duplicate device add to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Ensures add_device with an initial role requires sufficient rank.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_add_device_with_initial_role_requires_sufficient_rank() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let member_role_rank =
        query_rank(owner, aranya_daemon_api::ObjectId::transmute(member_role)).await?;

    // Assign member role to membera
    owner
        .actions()
        .assign_role(device_id(membera)?, member_role)
        .await
        .context("assigning member role should succeed")?;

    membera
        .sync_expect(owner, None)
        .await
        .context("membera unable to sync owner state")?;

    let (candidate, _store) = ctx
        .new_client("candidate", owner.graph_id)
        .await
        .context("unable to create candidate device")?;

    // Member lacks AddDevice permission, so this should fail
    let err = membera
        .actions()
        .add_device_with_rank(
            DeviceKeyBundle::try_from(&candidate.pk)?,
            Some(member_role),
            (member_role_rank.saturating_sub(1)).into(),
        )
        .await
        .expect_err("expected add_device with initial role to fail without AddDevice permission");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_role_requires_unassigned_device() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let admin = team.admin;

    let roles = load_default_roles(owner).await?;
    let operator_role = role_id_by_name(&roles, "operator");

    let err = owner
        .actions()
        .assign_role(device_id(admin)?, operator_role)
        .await
        .expect_err("expected assigning second role to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Rejects role assignment when the target device is unknown.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_role_rejects_unknown_device() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");

    let (extra, _store) = ctx
        .new_client("unknown-device", owner.graph_id)
        .await
        .context("unable to create extra device")?;
    let bogus_device_id = extra.pk.ident_pk.id()?;

    let err = owner
        .actions()
        .assign_role(bogus_device_id, member_role)
        .await
        .expect_err("expected assigning role to unknown device to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Rejects role assignment when the target role is unknown.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_role_rejects_unknown_role() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");

    let mut bogus_role_bytes: [u8; 32] = member_role.into();
    bogus_role_bytes[0] ^= 0xFF;
    let bogus_role = RoleId::from(bogus_role_bytes);

    let err = owner
        .actions()
        .assign_role(device_id(membera)?, bogus_role)
        .await
        .expect_err("expected assigning unknown role to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_role_self_assignment_rejected() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");

    let err = owner
        .actions()
        .assign_role(device_id(owner)?, owner_role)
        .await
        .expect_err("expected assigning role to self to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Requires create_label_with_rank to use a valid rank.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_create_label_requires_valid_rank() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    // Create a label with owner role rank
    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let owner_role_rank =
        query_rank(owner, aranya_daemon_api::ObjectId::transmute(owner_role)).await?;
    owner
        .actions()
        .create_label_with_rank(text!("TEST_LABEL"), owner_role_rank.into())
        .await
        .context("label creation with valid rank should succeed")?;

    Ok(())
}

/// Ensures delete_label enforces permissions and blocks reuse afterward.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_delete_label_enforces_permissions_and_removes_access() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let operator = team.operator;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let owner_role_rank =
        query_rank(owner, aranya_daemon_api::ObjectId::transmute(owner_role)).await?;

    let effects = owner
        .actions()
        .create_label_with_rank(text!("DELETE_LABEL_GUARD"), owner_role_rank.into())
        .await
        .context("label creation should succeed")?;
    let label_id = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(LabelId::from_base(e.label_id)),
            _ => None,
        })
        .expect("expected label created effect");

    operator
        .sync_expect(owner, None)
        .await
        .context("operator unable to sync owner state")?;

    let err = operator
        .actions()
        .delete_label(label_id)
        .await
        .expect_err("expected delete_label without rights to fail");
    expect_not_authorized(err);

    owner
        .actions()
        .delete_label(label_id)
        .await
        .context("owner should be able to delete label")?;

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_role_requires_delegated_permission() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let membera = team.membera;
    let memberb = team.memberb;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");

    membera
        .sync_expect(owner, None)
        .await
        .context("membera unable to sync owner state")?;

    // Member role does not have AssignRole permission, so this should fail.
    let err = membera
        .actions()
        .assign_role(device_id(memberb)?, member_role)
        .await
        .expect_err("expected assigning role without AssignRole permission to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Confirms add_perm_to_role requires CanChangeRolePerms delegation.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_add_perm_to_role_requires_management_delegation() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let admin = team.admin;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync owner state")?;

    let err = admin
        .actions()
        .add_perm_to_role(member_role, Perm::CanUseAfc)
        .await
        .expect_err("expected add_perm_to_role without delegation to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Rejects remove_perm_from_role when the permission does not exist.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_remove_perm_from_role_requires_existing_permission() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");

    let err = owner
        .actions()
        .remove_perm_from_role(member_role, Perm::AssignLabel)
        .await
        .expect_err("expected remove_perm_from_role on missing perm to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_change_role_requires_remaining_owner() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let admin_role = role_id_by_name(&roles, "admin");

    // Attempting to change the last owner to admin should fail
    let err = owner
        .actions()
        .change_role(device_id(owner)?, owner_role, admin_role)
        .await
        .expect_err("expected changing last owner to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Guards change_role against no-op transitions.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_change_role_rejects_same_role_transition() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");

    owner
        .actions()
        .assign_role(device_id(membera)?, member_role)
        .await
        .context("assigning member role should succeed")?;

    let err = owner
        .actions()
        .change_role(device_id(membera)?, member_role, member_role)
        .await
        .expect_err("expected no-op change_role to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Guards change_role when old_role_id mismatches the device's assignment.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_change_role_rejects_mismatched_current_role() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let operator_role = role_id_by_name(&roles, "operator");

    owner
        .actions()
        .assign_role(device_id(membera)?, member_role)
        .await
        .context("assigning member role should succeed")?;

    let err = owner
        .actions()
        .change_role(device_id(membera)?, operator_role, member_role)
        .await
        .expect_err("expected change_role with wrong old_role to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Ensures terminate_team validates the supplied team id.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_terminate_team_requires_matching_id() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let mut bogus_team_bytes = *owner.graph_id.as_array();
    bogus_team_bytes[0] ^= 0x24;
    let bogus_team = GraphId::from(bogus_team_bytes);

    let err = owner
        .actions()
        .terminate_team(bogus_team)
        .await
        .expect_err("expected terminate_team with mismatched id to fail");
    expect_not_authorized(err);

    Ok(())
}
