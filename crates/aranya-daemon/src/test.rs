//! Test module for aranya-daemon.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    rust_2018_idioms
)]

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    net::Ipv4Addr,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use aranya_aqc_util::LabelId;
use aranya_crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    keystore::fs_keystore::Store,
    policy::RoleId,
    Csprng, DeviceId, Rng,
};
use aranya_daemon_api::{text, TeamId};
use aranya_keygen::{KeyBundle, PublicKeys};
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
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    task::{self, AbortHandle},
};

use crate::{
    actions::Actions,
    api::EffectReceiver,
    aranya,
    policy::{ChanOp, Effect, KeyBundle as DeviceKeyBundle},
    sync::{
        self,
        task::{quic::PskStore, PeerCacheKey, PeerCacheMap, SyncPeer},
    },
    vm_policy::{PolicyEngine, POLICY_SOURCE},
    AranyaStore, InvalidGraphs,
};

// Aranya graph client for testing.
type TestClient =
    aranya::Client<PolicyEngine<DefaultEngine, Store>, LinearStorageProvider<FileManager>>;

type TestState = sync::task::quic::State;
// Aranya sync client for testing.
type TestSyncer = sync::task::Syncer<TestState>;

// Aranya sync server for testing.
type TestServer = sync::task::quic::Server<
    PolicyEngine<DefaultEngine, Store>,
    LinearStorageProvider<FileManager>,
>;

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
        sync_local_addr: Addr,
        pk: PublicKeys<DefaultCipherSuite>,
        graph_id: GraphId,
        syncer: TestSyncer,
        effect_recv: EffectReceiver,
    ) -> Result<Self> {
        let waiter = ready::Waiter::new(1);
        let notifier = waiter.notifier();
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
            .sync(&SyncPeer::new(device.sync_local_addr, self.graph_id))
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
        self.syncer.client().actions(&self.graph_id)
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

        let caches = PeerCacheMap::new(Mutex::new(BTreeMap::new()));

        let (syncer, server, local_addr, pk, psk_store, effects_recv) = {
            let mut store = {
                let path = root.join("keystore");
                fs::create_dir_all(&path)?;
                Store::open(path).map(AranyaStore::new)?
            };
            let (mut eng, _) = DefaultEngine::<Rng>::from_entropy(Rng);
            let bundle = KeyBundle::generate(&mut eng, &mut store)
                .context("unable to generate `KeyBundle`")?;

            let storage_dir = root.join("storage");
            fs::create_dir_all(&storage_dir)?;

            let pk = bundle.public_keys(&mut eng, &store)?;

            let graph = ClientState::new(
                PolicyEngine::new(
                    POLICY_SOURCE,
                    eng,
                    store.try_clone().context("unable to clone keystore")?,
                    bundle.device_id,
                )?,
                LinearStorageProvider::new(FileManager::new(&storage_dir)?),
            );

            let aranya = Arc::new(Mutex::new(graph));
            let client = TestClient::new(Arc::clone(&aranya));
            let local_addr = Addr::from((Ipv4Addr::LOCALHOST, 0));
            let psk_store = PskStore::new([]);
            let psk_store = Arc::new(psk_store);

            let (syncer, conn_map, conn_rx, effects_recv) = {
                let (send_effects, effect_recv) = mpsc::channel(1);
                let (syncer, _sync_peers, conn_map, conn_rx) = TestSyncer::new(
                    client.clone(),
                    send_effects,
                    InvalidGraphs::default(),
                    psk_store.clone(),
                    Addr::from((Ipv4Addr::LOCALHOST, 0)),
                    caches.clone(),
                )?;

                (syncer, conn_map, conn_rx, effect_recv)
            };

            let server: TestServer = TestServer::new(
                client.clone(),
                &local_addr,
                psk_store.clone(),
                conn_map,
                conn_rx,
                caches.clone(),
            )
            .await?;
            let local_addr = server.local_addr()?;
            (syncer, server, local_addr, pk, psk_store, effects_recv)
        };

        Ok((
            TestDevice::new(server, local_addr.into(), pk, id, syncer, effects_recv)?,
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
        let _team_id = TeamId::from(*owner.graph_id.as_array());

        // Get owner role ID from existing roles
        let role_effects = owner.actions().query_team_roles().await?;
        let roles: Vec<_> = role_effects
            .into_iter()
            .filter_map(|e| {
                if let Effect::QueryTeamRolesResult(result) = e {
                    Some(aranya_daemon_api::Role {
                        id: result.role_id.into(),
                        name: result.name,
                        author_id: result.author_id.into(),
                        default: result.default,
                    })
                } else {
                    None
                }
            })
            .collect();
        let owner_role = roles
            .into_iter()
            .find(|role| role.name.as_str() == "owner" && role.default)
            .context("owner role not found")?;

        // Setup default roles (admin, operator, member)
        owner
            .actions()
            .setup_default_roles(owner_role.id.into_id().into())
            .await
            .context("unable to setup default roles")?;

        // Now get the role IDs for admin and operator
        let all_role_effects = owner.actions().query_team_roles().await?;
        let all_roles: Vec<_> = all_role_effects
            .into_iter()
            .filter_map(|e| {
                if let Effect::QueryTeamRolesResult(result) = e {
                    Some(aranya_daemon_api::Role {
                        id: result.role_id.into(),
                        name: result.name,
                        author_id: result.author_id.into(),
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

        owner
            .actions()
            .add_device(DeviceKeyBundle::try_from(&admin.pk)?, None)
            .await
            .context("unable to add admin member")?;
        owner
            .actions()
            .assign_role(admin.pk.ident_pk.id()?, admin_role.id.into_id().into())
            .await
            .context("unable to elevate admin role")?;
        admin.sync_expect(owner, None).await?;

        let admin_caches = admin.syncer.get_peer_caches();
        let owner_key = PeerCacheKey {
            addr: owner.sync_local_addr,
            id: admin.graph_id,
        };
        let admin_cache_size = admin_caches
            .lock()
            .await
            .get(&owner_key)
            .unwrap()
            .heads()
            .len();
        assert!(admin_cache_size > 0);

        owner
            .actions()
            .add_device(DeviceKeyBundle::try_from(&operator.pk)?, None)
            .await
            .context("unable to add operator member")?;
        owner
            .actions()
            .assign_role(
                operator.pk.ident_pk.id()?,
                operator_role.id.into_id().into(),
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

        admin
            .actions()
            .add_device(DeviceKeyBundle::try_from(&membera.pk)?, None)
            .await
            .context("unable to add membera member")?;
        membera.sync_expect(admin, None).await?;
        admin
            .actions()
            .add_device(DeviceKeyBundle::try_from(&memberb.pk)?, None)
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
            text!("AddDevice"),
            "admin should already grant AddDevice",
        ),
        (
            admin_role,
            text!("RemoveDevice"),
            "admin should already grant RemoveDevice",
        ),
        (
            admin_role,
            text!("CreateLabel"),
            "admin should already grant CreateLabel",
        ),
        (
            admin_role,
            text!("DeleteLabel"),
            "admin should already grant DeleteLabel",
        ),
        (
            admin_role,
            text!("ChangeLabelManagingRole"),
            "admin should already grant ChangeLabelManagingRole",
        ),
        (
            admin_role,
            text!("AssignRole"),
            "admin should already grant AssignRole",
        ),
        (
            admin_role,
            text!("RevokeRole"),
            "admin should already grant RevokeRole",
        ),
        (
            operator_role,
            text!("AssignLabel"),
            "operator should already grant AssignLabel",
        ),
        (
            operator_role,
            text!("RevokeLabel"),
            "operator should already grant RevokeLabel",
        ),
        (
            operator_role,
            text!("SetAqcNetworkName"),
            "operator should already grant SetAqcNetworkName",
        ),
        (
            operator_role,
            text!("UnsetAqcNetworkName"),
            "operator should already grant UnsetAqcNetworkName",
        ),
        (
            operator_role,
            text!("AssignRole"),
            "operator should already grant AssignRole",
        ),
        (
            operator_role,
            text!("RevokeRole"),
            "operator should already grant RevokeRole",
        ),
        (
            member_role,
            text!("CanUseAqc"),
            "member should already grant CanUseAqc",
        ),
        (
            member_role,
            text!("CreateAqcUniChannel"),
            "member should already grant CreateAqcUniChannel",
        ),
        (
            member_role,
            text!("CreateAqcBidiChannel"),
            "member should already grant CreateAqcBidiChannel",
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
            roles.insert(result.name.to_string(), result.role_id.into());
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

    owner
        .actions()
        .add_device(DeviceKeyBundle::try_from(&extra.pk)?, None)
        .await
        .context("initial add should succeed")?;

    let err = owner
        .actions()
        .add_device(DeviceKeyBundle::try_from(&extra.pk)?, None)
        .await
        .expect_err("expected duplicate device add to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Ensures add_device with an initial role fails without delegated authority.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_add_device_with_initial_role_requires_delegation() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let admin = team.admin;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let operator_role = role_id_by_name(&roles, "operator");
    let admin_role = role_id_by_name(&roles, "admin");

    owner
        .actions()
        .assign_role_management_perm(operator_role, admin_role, text!("CanAssignRole"))
        .await
        .context("delegating operator CanAssignRole should succeed")?;

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync owner state")?;

    let (candidate, _store) = ctx
        .new_client("candidate", owner.graph_id)
        .await
        .context("unable to create candidate device")?;

    let err = admin
        .actions()
        .add_device(DeviceKeyBundle::try_from(&candidate.pk)?, Some(member_role))
        .await
        .expect_err("expected add_device with initial role to fail without delegation");
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
    let admin = team.admin;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let admin_role = role_id_by_name(&roles, "admin");

    owner
        .actions()
        .assign_role_management_perm(member_role, admin_role, text!("CanAssignRole"))
        .await
        .context("delegating CanAssignRole should succeed")?;

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync delegation")?;

    let (extra, _store) = ctx
        .new_client("unknown-device", owner.graph_id)
        .await
        .context("unable to create extra device")?;
    let bogus_device_id = extra.pk.ident_pk.id()?;

    let err = admin
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

    let mut bogus_role_bytes: [u8; 32] = member_role.into_id().into();
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
async fn test_assign_role_management_perm_is_unique() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let admin_role = role_id_by_name(&roles, "admin");

    owner
        .actions()
        .assign_role_management_perm(member_role, admin_role, text!("CanAssignRole"))
        .await
        .context("first delegation should succeed")?;

    let err = owner
        .actions()
        .assign_role_management_perm(member_role, admin_role, text!("CanAssignRole"))
        .await
        .expect_err("expected duplicate delegation to fail");
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

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_revoke_role_management_perm_requires_existing_fact() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let admin_role = role_id_by_name(&roles, "admin");

    owner
        .actions()
        .assign_role_management_perm(member_role, admin_role, text!("CanRevokeRole"))
        .await
        .context("granting management perm should succeed")?;

    owner
        .actions()
        .revoke_role_management_perm(member_role, admin_role, text!("CanRevokeRole"))
        .await
        .context("first revocation should succeed")?;

    let err = owner
        .actions()
        .revoke_role_management_perm(member_role, admin_role, text!("CanRevokeRole"))
        .await
        .expect_err("expected second revocation to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_role_management_perm_requires_ownership() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let admin = team.admin;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let admin_role = role_id_by_name(&roles, "admin");

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync owner state")?;

    let err = admin
        .actions()
        .assign_role_management_perm(member_role, admin_role, text!("CanAssignRole"))
        .await
        .expect_err("expected assigning management perm without ownership to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Requires create_label to reference an existing managing role.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_create_label_requires_existing_managing_role() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");

    let mut bogus_role_bytes: [u8; 32] = owner_role.into_id().into();
    bogus_role_bytes[0] ^= 0x55;
    let bogus_role = RoleId::from(bogus_role_bytes);

    let err = owner
        .actions()
        .create_label(text!("MISSING_MANAGER"), bogus_role)
        .await
        .expect_err("expected create_label with unknown manager to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_add_label_managing_role_is_unique() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let admin_role = role_id_by_name(&roles, "admin");

    let effects = owner
        .actions()
        .create_label(text!("TEST_LABEL"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id),
            _ => None,
        })
        .expect("expected label created effect")
        .into();

    owner
        .actions()
        .add_label_managing_role(label_id, admin_role)
        .await
        .context("first managing role addition should succeed")?;

    let err = owner
        .actions()
        .add_label_managing_role(label_id, admin_role)
        .await
        .expect_err("expected duplicate managing role to fail");
    expect_not_authorized(err);

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

    let effects = owner
        .actions()
        .create_label(text!("DELETE_LABEL_GUARD"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id.into()),
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

    let err = owner
        .actions()
        .assign_label_to_role(owner_role, label_id, ChanOp::SendRecv)
        .await
        .expect_err("expected assigning deleted label to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Requires add_label_managing_role callers to hold label management rights.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_add_label_managing_role_requires_delegation() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let admin = team.admin;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let operator_role = role_id_by_name(&roles, "operator");

    let effects = owner
        .actions()
        .create_label(text!("LABEL_DELEGATION"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id.into()),
            _ => None,
        })
        .expect("expected label created effect");

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync owner state")?;

    let err = admin
        .actions()
        .add_label_managing_role(label_id, operator_role)
        .await
        .expect_err("expected add_label_managing_role without delegation to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Enforces label and role existence when adding a managing role.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_add_label_managing_role_requires_existing_ids() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let admin_role = role_id_by_name(&roles, "admin");

    let effects = owner
        .actions()
        .create_label(text!("LABEL_FOREIGN_KEY"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id.into()),
            _ => None,
        })
        .expect("expected label created effect");

    let bogus_label = LabelId::from([0x33; 32]);

    let mut bogus_role_bytes: [u8; 32] = admin_role.into_id().into();
    bogus_role_bytes[0] ^= 0x77;
    let bogus_role = RoleId::from(bogus_role_bytes);

    let err = owner
        .actions()
        .add_label_managing_role(bogus_label, admin_role)
        .await
        .expect_err("expected add_label_managing_role with unknown label to fail");
    expect_not_authorized(err);

    let err = owner
        .actions()
        .add_label_managing_role(label_id, bogus_role)
        .await
        .expect_err("expected add_label_managing_role with unknown role to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_role_requires_delegated_permission() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let operator = team.operator;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");

    operator
        .sync_expect(owner, None)
        .await
        .context("operator unable to sync owner state")?;

    let err = operator
        .actions()
        .assign_role(device_id(membera)?, member_role)
        .await
        .expect_err("expected assigning role without delegation to fail");
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
        .add_perm_to_role(member_role, text!("CanUseAqc"))
        .await
        .expect_err("expected add_perm_to_role without delegation to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Rejects add_perm_to_role when the permission string is invalid.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_add_perm_to_role_rejects_invalid_permission() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let admin = team.admin;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let admin_role = role_id_by_name(&roles, "admin");

    owner
        .actions()
        .assign_role_management_perm(member_role, admin_role, text!("CanChangeRolePerms"))
        .await
        .context("delegating CanChangeRolePerms should succeed")?;

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync delegation")?;

    let err = admin
        .actions()
        .add_perm_to_role(member_role, text!("DefinitelyNotAPerm"))
        .await
        .expect_err("expected invalid permission to be rejected");
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
    let admin = team.admin;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let admin_role = role_id_by_name(&roles, "admin");

    owner
        .actions()
        .assign_role_management_perm(member_role, admin_role, text!("CanChangeRolePerms"))
        .await
        .context("delegating CanChangeRolePerms should succeed")?;

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync delegation")?;

    let err = admin
        .actions()
        .remove_perm_from_role(member_role, text!("AssignLabel"))
        .await
        .expect_err("expected remove_perm_from_role on missing perm to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_revoke_label_managing_role_requires_existing_fact() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let admin_role = role_id_by_name(&roles, "admin");

    let effects = owner
        .actions()
        .create_label(text!("TEST_LABEL_REVOKE"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id),
            _ => None,
        })
        .expect("expected label created effect")
        .into();

    owner
        .actions()
        .add_label_managing_role(label_id, admin_role)
        .await
        .context("first managing role addition should succeed")?;

    owner
        .actions()
        .revoke_label_managing_role(label_id, admin_role)
        .await
        .context("first managing role revocation should succeed")?;

    let err = owner
        .actions()
        .revoke_label_managing_role(label_id, admin_role)
        .await
        .expect_err("expected duplicate revocation to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_label_to_device_is_unique() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");

    let effects = owner
        .actions()
        .create_label(text!("DEVICE_LABEL"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id),
            _ => None,
        })
        .expect("expected label created effect")
        .into();

    owner
        .actions()
        .set_aqc_network_name(device_id(membera)?, text!("membera.local"))
        .await
        .context("setting network name should succeed")?;

    owner
        .actions()
        .assign_label_to_device(device_id(membera)?, label_id, ChanOp::SendRecv)
        .await
        .context("first label assignment should succeed")?;

    let err = owner
        .actions()
        .assign_label_to_device(device_id(membera)?, label_id, ChanOp::SendRecv)
        .await
        .expect_err("expected duplicate label assignment to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_label_to_current_role_rejected() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");

    owner
        .actions()
        .add_perm_to_role(owner_role, text!("CanUseAqc"))
        .await
        .context("adding CanUseAqc to owner role should succeed")?;

    let effects = owner
        .actions()
        .create_label(text!("SELF_ROLE_LABEL"), owner_role.into_id().into())
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id),
            _ => None,
        })
        .expect("expected label created effect")
        .into();

    let err = owner
        .actions()
        .assign_label_to_role(owner_role, label_id, ChanOp::SendRecv)
        .await
        .expect_err("expected assigning label to managing role to fail");
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
    let admin = team.admin;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let admin_role = role_id_by_name(&roles, "admin");

    // Allow the admin role to manage both the owner and admin roles.
    owner
        .actions()
        .assign_role_management_perm(owner_role, admin_role, text!("CanAssignRole"))
        .await
        .context("delegating owner CanAssignRole should succeed")?;
    owner
        .actions()
        .assign_role_management_perm(owner_role, admin_role, text!("CanRevokeRole"))
        .await
        .context("delegating owner CanRevokeRole should succeed")?;
    owner
        .actions()
        .assign_role_management_perm(admin_role, admin_role, text!("CanAssignRole"))
        .await
        .context("delegating admin CanAssignRole should succeed")?;

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync owner delegations")?;

    let err = admin
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
    let admin = team.admin;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let admin_role = role_id_by_name(&roles, "admin");

    owner
        .actions()
        .assign_role_management_perm(member_role, admin_role, text!("CanAssignRole"))
        .await
        .context("delegating CanAssignRole should succeed")?;
    owner
        .actions()
        .assign_role_management_perm(member_role, admin_role, text!("CanRevokeRole"))
        .await
        .context("delegating CanRevokeRole should succeed")?;

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync delegations")?;

    owner
        .actions()
        .assign_role(device_id(membera)?, member_role)
        .await
        .context("assigning member role should succeed")?;

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync member assignment")?;

    let err = admin
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
    let admin = team.admin;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");
    let operator_role = role_id_by_name(&roles, "operator");
    let admin_role = role_id_by_name(&roles, "admin");

    owner
        .actions()
        .assign_role_management_perm(member_role, admin_role, text!("CanAssignRole"))
        .await
        .context("delegating CanAssignRole should succeed")?;
    owner
        .actions()
        .assign_role_management_perm(operator_role, admin_role, text!("CanRevokeRole"))
        .await
        .context("delegating operator CanRevokeRole should succeed")?;

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync delegations")?;

    owner
        .actions()
        .assign_role(device_id(membera)?, member_role)
        .await
        .context("assigning member role should succeed")?;

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync member assignment")?;

    let err = admin
        .actions()
        .change_role(device_id(membera)?, operator_role, member_role)
        .await
        .expect_err("expected change_role with wrong old_role to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_label_to_role_requires_can_use_aqc() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let admin_role = role_id_by_name(&roles, "admin");

    let effects = owner
        .actions()
        .create_label(text!("ROLE_NEEDS_AQC"), owner_role.into_id().into())
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id),
            _ => None,
        })
        .expect("expected label created effect")
        .into();

    let err = owner
        .actions()
        .assign_label_to_role(admin_role, label_id, ChanOp::SendRecv)
        .await
        .expect_err("expected assigning label to non-AQC role to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_revoke_label_from_device_requires_existing_fact() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");

    let effects = owner
        .actions()
        .create_label(text!("DEVICE_LABEL_REVOKE"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id),
            _ => None,
        })
        .expect("expected label created effect")
        .into();

    owner
        .actions()
        .set_aqc_network_name(device_id(membera)?, text!("membera.revoke"))
        .await
        .context("setting network name should succeed")?;

    owner
        .actions()
        .assign_label_to_device(device_id(membera)?, label_id, ChanOp::SendRecv)
        .await
        .context("label assignment should succeed")?;

    owner
        .actions()
        .revoke_label_from_device(device_id(membera)?, label_id)
        .await
        .context("first revocation should succeed")?;

    let err = owner
        .actions()
        .revoke_label_from_device(device_id(membera)?, label_id)
        .await
        .expect_err("expected duplicate revocation to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_label_to_device_self_rejected() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");

    owner
        .actions()
        .set_aqc_network_name(device_id(owner)?, text!("owner.self"))
        .await
        .context("setting owner network name should succeed")?;

    let effects = owner
        .actions()
        .create_label(text!("DEVICE_SELF_LABEL"), owner_role.into_id().into())
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id),
            _ => None,
        })
        .expect("expected label created effect")
        .into();

    let err = owner
        .actions()
        .assign_label_to_device(device_id(owner)?, label_id, ChanOp::SendRecv)
        .await
        .expect_err("expected assigning label to self to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_label_to_device_requires_network_id() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");

    let effects = owner
        .actions()
        .create_label(text!("DEVICE_NEEDS_NET"), owner_role.into_id().into())
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id),
            _ => None,
        })
        .expect("expected label created effect")
        .into();

    let err = owner
        .actions()
        .assign_label_to_device(device_id(membera)?, label_id, ChanOp::SendRecv)
        .await
        .expect_err("expected assigning label without network id to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_remove_device_invalidates_direct_labels() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");

    let effects = owner
        .actions()
        .create_label(text!("DEVICE_REMOVAL_GUARD"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id),
            _ => None,
        })
        .expect("expected label created effect")
        .into();

    owner
        .actions()
        .set_aqc_network_name(device_id(membera)?, text!("membera.remove-guard"))
        .await
        .context("setting network name should succeed")?;

    owner
        .actions()
        .assign_label_to_device(device_id(membera)?, label_id, ChanOp::SendRecv)
        .await
        .context("label assignment should succeed")?;

    owner
        .actions()
        .remove_device(device_id(membera)?)
        .await
        .context("device removal should succeed even with direct labels")?;

    // Re-add the device with the same key material.
    owner
        .actions()
        .add_device(DeviceKeyBundle::try_from(&membera.pk)?, None)
        .await
        .context("re-adding removed device should succeed")?;

    let member_role = role_id_by_name(&roles, "member");

    owner
        .actions()
        .assign_role(device_id(membera)?, member_role.into_id().into())
        .await
        .context("reassigning member role should succeed")?;

    // Direct label assignments from the previous incarnation must no longer apply.
    let query_effects = owner
        .actions()
        .query_labels_assigned_to_device(device_id(membera)?)
        .await
        .context("querying device labels should succeed")?;

    let has_results = query_effects
        .into_iter()
        .any(|effect| matches!(effect, Effect::QueryLabelsAssignedToDeviceResult(_)));
    assert!(
        !has_results,
        "expected no residual direct label assignments after device removal"
    );

    Ok(())
}

/// Checks label reassignment after device removal bumps the generation.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_assign_label_to_device_updates_after_readdition() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let operator = team.operator;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let operator_role = role_id_by_name(&roles, "operator");
    let member_role = role_id_by_name(&roles, "member");

    owner
        .actions()
        .assign_role(device_id(membera)?, member_role)
        .await
        .context("assigning member role should succeed")?;
    membera.sync_expect(owner, None).await?;
    operator.sync_expect(owner, None).await?;

    let effects = owner
        .actions()
        .create_label(text!("LABEL_READD"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id.into()),
            _ => None,
        })
        .expect("expected label created effect");

    owner
        .actions()
        .add_label_managing_role(label_id, operator_role)
        .await
        .context("delegating label management to operator should succeed")?;

    operator
        .sync_expect(owner, None)
        .await
        .context("operator unable to sync delegated label management")?;

    operator
        .actions()
        .set_aqc_network_name(device_id(membera)?, text!("membera.readd"))
        .await
        .context("setting network name should succeed")?;

    operator
        .actions()
        .assign_label_to_device(device_id(membera)?, label_id, ChanOp::SendRecv)
        .await
        .context("initial label assignment should succeed")?;

    owner
        .sync_expect(operator, None)
        .await
        .context("owner unable to sync operator updates")?;

    owner
        .actions()
        .remove_device(device_id(membera)?)
        .await
        .context("device removal should succeed")?;

    owner
        .actions()
        .add_device(DeviceKeyBundle::try_from(&membera.pk)?, None)
        .await
        .context("re-adding device should succeed")?;

    owner
        .actions()
        .assign_role(device_id(membera)?, member_role)
        .await
        .context("reassigning member role should succeed")?;

    operator
        .sync_expect(owner, None)
        .await
        .context("operator unable to sync re-added device")?;

    operator
        .actions()
        .set_aqc_network_name(device_id(membera)?, text!("membera.readd"))
        .await
        .context("resetting network name should succeed")?;

    let query_effects = owner
        .actions()
        .query_labels_assigned_to_device(device_id(membera)?)
        .await
        .context("querying labels should succeed")?;
    let has_results = query_effects
        .into_iter()
        .any(|effect| matches!(effect, Effect::QueryLabelsAssignedToDeviceResult(_)));
    assert!(
        !has_results,
        "expected no active label assignments before reassignment"
    );

    operator
        .actions()
        .assign_label_to_device(device_id(membera)?, label_id, ChanOp::SendRecv)
        .await
        .context("label reassignment should succeed after generation bump")?;

    Ok(())
}

/// Rejects setting an AQC network name for unknown devices.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_set_aqc_network_name_requires_existing_device() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let operator = team.operator;

    operator
        .sync_expect(owner, None)
        .await
        .context("operator unable to sync owner state")?;

    let (extra, _store) = ctx
        .new_client("missing-device", owner.graph_id)
        .await
        .context("unable to create extra client")?;
    let bogus_device_id = extra.pk.ident_pk.id()?;

    let err = operator
        .actions()
        .set_aqc_network_name(bogus_device_id, text!("ghost.net"))
        .await
        .expect_err("expected setting network name for unknown device to fail");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_set_aqc_network_name_requires_permission() -> Result<()> {
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
        .context("owner should be able to assign member role")?;
    membera.sync_expect(owner, None).await?;

    let err = membera
        .actions()
        .set_aqc_network_name(device_id(membera)?, text!("membera.net"))
        .await
        .expect_err("expected setting network name without permission to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Verifies removing a device clears its stored network identifier.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_remove_device_clears_network_id() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let operator = team.operator;
    let membera = team.membera;

    operator
        .sync_expect(owner, None)
        .await
        .context("operator unable to sync owner state")?;

    operator
        .actions()
        .set_aqc_network_name(device_id(membera)?, text!("membera.cleanup"))
        .await
        .context("setting network name should succeed")?;

    owner
        .actions()
        .remove_device(device_id(membera)?)
        .await
        .context("device removal should succeed")?;

    owner
        .actions()
        .add_device(DeviceKeyBundle::try_from(&membera.pk)?, None)
        .await
        .context("re-adding device should succeed")?;

    let query_effects = owner
        .actions()
        .query_aqc_net_id(device_id(membera)?)
        .await
        .context("querying network id should succeed")?;
    let mut saw_result = false;
    for effect in query_effects {
        if let Effect::QueryAqcNetIdResult(result) = effect {
            saw_result = true;
            assert!(
                result.net_id.is_none(),
                "expected no network id after device re-addition"
            );
        }
    }
    assert!(saw_result, "expected query_aqc_net_id to emit a result");

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_query_aqc_network_names_requires_active_team() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    owner
        .actions()
        .set_aqc_network_name(device_id(owner)?, text!("owner.net"))
        .await
        .context("setting network name should succeed")?;

    let team_id = TeamId::from(*owner.graph_id.as_array());
    owner
        .actions()
        .terminate_team(team_id.into_id())
        .await
        .context("terminating team should succeed")?;

    let err = owner
        .actions()
        .query_aqc_network_names()
        .await
        .expect_err("expected query on terminated team to fail");
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

    let team_id = TeamId::from(*owner.graph_id.as_array());
    let mut bogus_team_bytes: [u8; 32] = team_id.into_id().into();
    bogus_team_bytes[0] ^= 0x24;
    let bogus_team = TeamId::from(bogus_team_bytes);

    let err = owner
        .actions()
        .terminate_team(bogus_team.into_id())
        .await
        .expect_err("expected terminate_team with mismatched id to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Requires AQC entries to exist before unsetting a member's network name.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_unset_aqc_network_name_requires_existing_entry() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;
    let operator = team.operator;
    let membera = team.membera;

    let roles = load_default_roles(owner).await?;
    let member_role = role_id_by_name(&roles, "member");

    owner
        .actions()
        .assign_role(device_id(membera)?, member_role)
        .await
        .context("assigning member role should succeed")?;
    membera.sync_expect(owner, None).await?;
    operator.sync_expect(owner, None).await?;

    operator
        .actions()
        .set_aqc_network_name(device_id(membera)?, text!("membera.unset"))
        .await
        .context("setting network name should succeed")?;

    operator
        .actions()
        .unset_aqc_network_name(device_id(membera)?)
        .await
        .context("first unset should succeed")?;

    let err = operator
        .actions()
        .unset_aqc_network_name(device_id(membera)?)
        .await
        .expect_err("expected second unset to fail due to missing entry");
    expect_not_authorized(err);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_remove_role_owner_requires_remaining_owner() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let owner = team.owner;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let admin_role = role_id_by_name(&roles, "admin");

    let err = owner
        .actions()
        .remove_role_owner(admin_role, owner_role)
        .await
        .expect_err("expected removing final role owner to fail");
    expect_not_authorized(err);

    Ok(())
}

/// Operators with label management rights cannot change label managing roles.
/// Only owners and admins with ChangeLabelManagingRole permission can.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_add_label_managing_role_requires_change_perm() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());
    let owner = team.owner;
    let admin = team.admin;
    let operator = team.operator;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let operator_role = role_id_by_name(&roles, "operator");
    let member_role = role_id_by_name(&roles, "member");

    // Create a label with owner as the managing role initially
    let effects = owner
        .actions()
        .create_label(text!("PRIVILEGE_TEST"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id.into()),
            _ => None,
        })
        .expect("expected label created effect");

    // Give operator the ability to manage the label
    owner
        .actions()
        .add_label_managing_role(label_id, operator_role)
        .await
        .context("owner should be able to add operator as managing role")?;

    // Sync operator to get the latest state
    operator
        .sync_expect(owner, None)
        .await
        .context("operator unable to sync owner state")?;

    // Operator should be able to manage the label (assign/revoke)
    // but should NOT be able to add managing roles
    let err = operator
        .actions()
        .add_label_managing_role(label_id, member_role)
        .await
        .expect_err("operator should not be able to add label managing roles");
    expect_not_authorized(err);

    // Admin should be able to add managing roles (has ChangeLabelManagingRole)
    // But first needs to be given management permission for this label
    owner
        .actions()
        .add_label_managing_role(label_id, role_id_by_name(&roles, "admin"))
        .await
        .context("owner should be able to add admin as managing role")?;

    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync owner state")?;
    admin
        .actions()
        .add_label_managing_role(label_id, member_role)
        .await
        .context("admin should be able to add label managing roles")?;

    // Owner should also be able to add managing roles (already tested implicitly above)

    Ok(())
}

/// Operators with label management rights cannot revoke label managing roles.
/// Only owners and admins with ChangeLabelManagingRole permission can.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_revoke_label_managing_role_requires_change_perm() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());
    let owner = team.owner;
    let admin = team.admin;
    let operator = team.operator;

    let roles = load_default_roles(owner).await?;
    let owner_role = role_id_by_name(&roles, "owner");
    let operator_role = role_id_by_name(&roles, "operator");
    let admin_role = role_id_by_name(&roles, "admin");

    // Create a label with owner as the managing role initially
    let effects = owner
        .actions()
        .create_label(text!("REVOKE_PRIVILEGE_TEST"), owner_role)
        .await
        .context("label creation should succeed")?;
    let label_id: LabelId = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::LabelCreated(e) => Some(e.label_id.into()),
            _ => None,
        })
        .expect("expected label created effect");

    // Add admin and operator as managing roles
    owner
        .actions()
        .add_label_managing_role(label_id, admin_role)
        .await
        .context("owner should be able to add admin as managing role")?;

    owner
        .actions()
        .add_label_managing_role(label_id, operator_role)
        .await
        .context("owner should be able to add operator as managing role")?;

    // Sync operator to get the latest state
    operator
        .sync_expect(owner, None)
        .await
        .context("operator unable to sync owner state")?;

    // Operator should NOT be able to revoke the admin managing role
    // even though operator can manage the label
    let err = operator
        .actions()
        .revoke_label_managing_role(label_id, admin_role)
        .await
        .expect_err("operator should not be able to revoke label managing roles");
    expect_not_authorized(err);

    // Admin should be able to revoke managing roles (has ChangeLabelManagingRole)
    admin
        .sync_expect(owner, None)
        .await
        .context("admin unable to sync owner state")?;
    admin
        .actions()
        .revoke_label_managing_role(label_id, operator_role)
        .await
        .context("admin should be able to revoke label managing roles")?;

    // Owner should be able to revoke remaining managing role
    owner
        .actions()
        .revoke_label_managing_role(label_id, admin_role)
        .await
        .context("owner should be able to revoke label managing roles")?;

    Ok(())
}
