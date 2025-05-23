#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::borrow_interior_mutable_const,
    clippy::declare_interior_mutable_const,
    rust_2018_idioms
)]

use std::{
    fs,
    net::Ipv4Addr,
    ops::{Deref, DerefMut},
    sync::{Arc, LazyLock},
};

use anyhow::{bail, Context, Result};
use aranya_crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    keystore::fs_keystore::Store,
    Csprng, Rng,
};
use aranya_daemon::{
    actions::Actions,
    aranya,
    policy::{Effect, KeyBundle as DeviceKeyBundle, Role},
    sync::{
        self,
        task::quic::{ClientPresharedKeys, Msg, ServerPresharedKeys},
    },
    vm_policy::{PolicyEngine, TEST_POLICY_1},
    AranyaStore,
};
use aranya_daemon_api::TeamId;
use aranya_keygen::{KeyBundle, PublicKeys};
use aranya_runtime::{
    storage::linear::{libc::FileManager, LinearStorageProvider},
    ClientState, GraphId,
};
use aranya_util::Addr;
use rustls::crypto::{hash::HashAlgorithm, PresharedKey};
use tempfile::{tempdir, TempDir};
use tokio::{
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    task::{self, AbortHandle},
};

const TEST_SYNC_PROTOCOL: sync::prot::SyncProtocol = sync::prot::SyncProtocol::V1;
type TestState = sync::task::quic::State;
// Aranya sync client for testing.
pub type TestSyncer = sync::task::Syncer<TestState>;

type TestClient =
    aranya::Client<PolicyEngine<DefaultEngine, Store>, LinearStorageProvider<FileManager>>;

// Aranya sync server for testing.
pub type TestServer = sync::task::quic::Server<
    PolicyEngine<DefaultEngine, Store>,
    LinearStorageProvider<FileManager>,
>;

const TEST_PSK: LazyLock<PresharedKey> = LazyLock::new(|| {
    PresharedKey::external(b"identity", b"secret")
        .expect("should not fail")
        .with_hash_alg(HashAlgorithm::SHA384)
        .expect("valid hash algorithm")
});

// checks if effects vector contains a particular type of effect.
#[macro_export]
macro_rules! contains_effect {
    ($effects:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {
        $effects.into_iter().any(|e| matches!(e, $pattern $(if $guard)?))
    }
}

pub struct TestDevice {
    /// Aranya sync client.
    pub syncer: TestSyncer,
    /// The Aranya graph ID.
    pub graph_id: GraphId,
    /// The address that the server is listening on.
    pub local_addr: Addr,
    /// Aborts the server task.
    handle: AbortHandle,
    /// Public keys
    pub pk: PublicKeys<DefaultCipherSuite>,
    effect_recv: Receiver<(GraphId, Vec<Effect>)>,
    server_keys: Arc<ServerPresharedKeys>,
    client_keys: Arc<ClientPresharedKeys>,
}

impl TestDevice {
    pub fn new(
        client: TestClient,
        server: TestServer,
        server_keys: Arc<ServerPresharedKeys>,
        local_addr: Addr,
        pk: PublicKeys<DefaultCipherSuite>,
        graph_id: GraphId,
    ) -> Result<Self> {
        let handle = task::spawn(async { server.serve().await }).abort_handle();
        let (state, client_keys) = TestState::new([])?;
        let (send, effect_recv) = mpsc::channel(1);
        let (syncer, _sync_peers) = TestSyncer::new(client, send, TEST_SYNC_PROTOCOL, state);
        Ok(Self {
            syncer,
            graph_id,
            local_addr,
            handle,
            pk,
            effect_recv,
            server_keys,
            client_keys,
        })
    }
}

impl TestDevice {
    pub async fn sync(&mut self, device: &TestDevice) -> Result<Vec<Effect>> {
        self.syncer
            .sync(&self.graph_id, &device.local_addr)
            .await
            .with_context(|| format!("unable to sync with peer at {}", device.local_addr))?;

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
        self.syncer.client.actions(&self.graph_id)
    }

    async fn create_team(
        &self,
        owner_keys: DeviceKeyBundle,
        nonce: Option<&[u8]>,
    ) -> Result<(GraphId, Vec<Effect>, Arc<PresharedKey>)> {
        match self.syncer.client.create_team(owner_keys, nonce).await {
            Ok((graph_id, effects)) => {
                let team_id = TeamId::from(*graph_id.as_array());
                let psk = Arc::new(TEST_PSK.clone());
                self.server_keys
                    .handle_msg(Msg::Insert((team_id, psk.clone())));
                self.client_keys
                    .handle_msg(Msg::Insert((team_id, psk.clone())));

                Ok((graph_id, effects, psk))
            }
            Err(e) => Err(e),
        }
    }

    async fn add_team(&self, psk: Arc<PresharedKey>) {
        let id = TeamId::from(*self.graph_id.as_array());
        self.server_keys.handle_msg(Msg::Insert((id, psk.clone())));
        self.client_keys.handle_msg(Msg::Insert((id, psk)));
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
        &self.syncer.client
    }
}

impl DerefMut for TestDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.syncer.client
    }
}

pub struct TestTeam {
    pub owner: TestDevice,
    pub admin: TestDevice,
    pub operator: TestDevice,
    pub membera: TestDevice,
    pub memberb: TestDevice,
}

impl TestTeam {
    pub fn new(clients: Vec<TestDevice>) -> Self {
        assert!(clients.len() >= 5);
        let mut iter = clients.into_iter();

        let (owner, admin, operator, membera, memberb) = (
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
        );
        TestTeam {
            owner,
            admin,
            operator,
            membera,
            memberb,
        }
    }
}

impl From<TestTeam> for Vec<TestDevice> {
    fn from(value: TestTeam) -> Self {
        vec![
            value.owner,
            value.admin,
            value.operator,
            value.membera,
            value.memberb,
        ]
    }
}

pub struct TestCtx {
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
    pub async fn new_client(&mut self, name: &str, id: GraphId) -> Result<TestDevice> {
        let addr = Addr::from((Ipv4Addr::LOCALHOST, 0)); // random port

        let root = self.dir.path().join(name);
        assert!(!root.try_exists()?, "duplicate client name: {name}");

        let (client, server, server_keys, local_addr, pk) = {
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
                    TEST_POLICY_1,
                    eng,
                    store.try_clone().context("unable to clone keystore")?,
                    bundle.device_id,
                )?,
                LinearStorageProvider::new(FileManager::new(&storage_dir)?),
            );

            let aranya = Arc::new(Mutex::new(graph));
            let client = TestClient::new(Arc::clone(&aranya));
            let (server, server_keys) =
                TestServer::new(client.clone(), &addr, TEST_SYNC_PROTOCOL, []).await?;
            let local_addr = server.local_addr()?;
            (client, server, server_keys, local_addr, pk)
        };

        TestDevice::new(client, server, server_keys, local_addr.into(), pk, id)
    }

    /// Creates `n` members.
    pub async fn new_group(&mut self, n: usize) -> Result<(Vec<TestDevice>, Arc<PresharedKey>)> {
        let mut clients = Vec::<TestDevice>::new();
        let mut members = 0..n;

        let Some(_) = members.next() else {
            bail!("Empty group");
        };

        // First member is the team owner
        let (graph_id, psk) = {
            let name = format!("client_{}", self.id);
            self.id += 1;

            let id = GraphId::default();
            let mut client = self
                .new_client(&name, id)
                .await
                .with_context(|| format!("unable to create client {name}"))?;
            let nonce = &mut [0u8; 16];
            Rng.fill_bytes(nonce);
            let (graph_id, _, psk) = client
                .create_team(DeviceKeyBundle::try_from(&client.pk)?, Some(nonce))
                .await?;
            client.graph_id = graph_id;
            clients.push(client);

            (graph_id, psk)
        };

        for _ in members {
            let name = format!("client_{}", self.id);
            self.id += 1;

            let mut client = self
                .new_client(&name, graph_id)
                .await
                .with_context(|| format!("unable to create client {name}"))?;

            client.graph_id = graph_id;
            clients.push(client);
        }
        Ok((clients, psk))
    }

    /// Creates default team.
    pub async fn new_team(&mut self) -> Result<Vec<TestDevice>> {
        let (clients, psk) = self
            .new_group(5)
            .await
            .context("unable to create clients")?;
        let mut team = TestTeam::new(clients);
        let owner = &mut team.owner;
        let admin = &mut team.admin;
        let operator = &mut team.operator;
        let membera = &mut team.membera;
        let memberb = &mut team.memberb;

        for member in [&admin, &operator, &membera, &memberb] {
            member.add_team(psk.clone()).await;
        }

        // team setup
        owner
            .actions()
            .add_member(DeviceKeyBundle::try_from(&admin.pk)?)
            .await
            .context("unable to add admin member")?;
        owner
            .actions()
            .assign_role(admin.pk.ident_pk.id()?, Role::Admin)
            .await
            .context("unable to elevate admin role")?;
        admin.sync(owner).await?;
        owner
            .actions()
            .add_member(DeviceKeyBundle::try_from(&operator.pk)?)
            .await
            .context("unable to add operator member")?;
        owner
            .actions()
            .assign_role(operator.pk.ident_pk.id()?, Role::Operator)
            .await
            .context("unable to elevate operator role")?;
        operator.sync(owner).await?;
        operator
            .actions()
            .add_member(DeviceKeyBundle::try_from(&membera.pk)?)
            .await
            .context("unable to add membera member")?;
        membera.sync(admin).await?;
        operator
            .actions()
            .add_member(DeviceKeyBundle::try_from(&memberb.pk)?)
            .await
            .context("unable to add memberb member")?;
        memberb.sync(admin).await?;

        owner.sync(operator).await?;
        admin.sync(operator).await?;
        membera.sync(operator).await?;
        memberb.sync(operator).await?;

        Ok(team.into())
    }
}
