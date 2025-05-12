#![allow(clippy::expect_used, clippy::indexing_slicing, rust_2018_idioms)]

use std::{
    fs,
    ops::{Deref, DerefMut},
    sync::Arc,
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
    sync,
    vm_policy::{PolicyEngine, TEST_POLICY_1},
    AranyaStore,
};
use aranya_keygen::{KeyBundle, PublicKeys};
use aranya_runtime::{
    storage::linear::{libc::FileManager, LinearStorageProvider},
    ClientState, GraphId,
};
use aranya_util::Addr;
use tempfile::{tempdir, TempDir};
use tokio::{
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    task::{self, AbortHandle},
};

pub type TestState = sync::task::quic::State;
// Aranya sync client for testing.
pub type TestSyncer = sync::task::Syncer<TestState>;

pub type TestClient = aranya::Client<
    PolicyEngine<DefaultEngine, Store>,
    LinearStorageProvider<FileManager>,
    DefaultEngine,
>;

// Aranya sync server for testing.
pub type TestServer = sync::task::quic::Server<
    PolicyEngine<DefaultEngine, Store>,
    LinearStorageProvider<FileManager>,
>;

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
}

impl TestDevice {
    pub fn new(
        client: TestClient,
        server: TestServer,
        local_addr: Addr,
        pk: PublicKeys<DefaultCipherSuite>,
        graph_id: GraphId,
    ) -> Result<Self> {
        let handle = task::spawn(async { server.serve().await }).abort_handle();
        let state = TestState::new()?;
        let (send, effect_recv) = mpsc::channel(1);
        let (syncer, _sync_peers) = TestSyncer::new(client, send, state);
        Ok(Self {
            syncer,
            graph_id,
            local_addr,
            handle,
            pk,
            effect_recv,
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
        let addr = Addr::new("127.0.0.1", 0)?; // random port

        let root = self.dir.path().join(name);
        assert!(!root.try_exists()?, "duplicate client name: {name}");

        let (client, server, local_addr, pk) = {
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
            let server = TestServer::new(Arc::clone(&aranya), &addr).await?;
            let local_addr = server.local_addr()?;
            (client, server, local_addr, pk)
        };

        TestDevice::new(client, server, local_addr.into(), pk, id)
    }

    /// Creates `n` members.
    pub async fn new_group(&mut self, n: usize) -> Result<Vec<TestDevice>> {
        let mut clients = Vec::<TestDevice>::new();
        for i in 0..n {
            let name = format!("client_{}", self.id);
            self.id += 1;

            let id = if i == 0 {
                GraphId::default()
            } else {
                clients[0].graph_id
            };
            let mut client = self
                .new_client(&name, id)
                .await
                .with_context(|| format!("unable to create client {name}"))?;
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
        Ok(clients)
    }

    /// Creates default team.
    pub async fn new_team(&mut self) -> Result<Vec<TestDevice>> {
        let clients = self
            .new_group(5)
            .await
            .context("unable to create clients")?;
        let mut team = TestTeam::new(clients);
        let owner = &mut team.owner;
        let admin = &mut team.admin;
        let operator = &mut team.operator;
        let membera = &mut team.membera;
        let memberb = &mut team.memberb;

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
