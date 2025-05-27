#![allow(clippy::expect_used, clippy::indexing_slicing, rust_2018_idioms)]

use std::{
    fs,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use anyhow::{Context, Result};
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
    vm_policy::{PolicyEngine, VecSink, TEST_POLICY_1},
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
    net::TcpListener,
    sync::Mutex,
    task::{self, AbortHandle},
};

// Aranya sync client for testing.
pub type TestClient =
    aranya::Client<PolicyEngine<DefaultEngine, Store>, LinearStorageProvider<FileManager>>;

// Aranya sync server for testing.
pub type TestServer =
    sync::tcp::Server<PolicyEngine<DefaultEngine, Store>, LinearStorageProvider<FileManager>>;

// checks if effects vector contains a particular type of effect.
#[macro_export]
macro_rules! contains_effect {
    ($effects:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {
        $effects.into_iter().any(|e| matches!(e, $pattern $(if $guard)?))
    }
}

pub struct TestDevice {
    /// Aranya sync client.
    aranya: TestClient,
    /// The Aranya graph ID.
    pub graph_id: GraphId,
    /// The address that the server is listening on.
    pub local_addr: Addr,
    /// Aborts the server task.
    handle: AbortHandle,
    /// Public keys
    pub pk: PublicKeys<DefaultCipherSuite>,
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
        Ok(Self {
            aranya: client,
            graph_id,
            local_addr,
            handle,
            pk,
        })
    }
}

impl TestDevice {
    pub async fn sync(&self, device: &TestDevice) -> Result<Vec<Effect>> {
        let mut sink = VecSink::new();
        self.sync_peer_tcp(self.graph_id, &mut sink, &device.local_addr)
            .await
            .with_context(|| format!("unable to sync with peer at {}", device.local_addr))?;
        Ok(sink.collect()?)
    }

    pub fn actions(
        &self,
    ) -> impl Actions<
        PolicyEngine<DefaultEngine<Rng>, Store>,
        LinearStorageProvider<FileManager>,
        DefaultEngine<Rng>,
    > {
        self.aranya.actions(&self.graph_id)
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
        &self.aranya
    }
}

impl DerefMut for TestDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.aranya
    }
}

pub struct TestTeam<'a> {
    pub owner: &'a TestDevice,
    pub admin: &'a TestDevice,
    pub operator: &'a TestDevice,
    pub membera: &'a TestDevice,
    pub memberb: &'a TestDevice,
}

impl<'a> TestTeam<'a> {
    pub fn new(clients: &'a [TestDevice]) -> Self {
        assert!(clients.len() >= 5);
        TestTeam {
            owner: &clients[0],
            admin: &clients[1],
            operator: &clients[2],
            membera: &clients[3],
            memberb: &clients[4],
        }
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
        let addr = Addr::new("localhost", 0)?; // random port

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

            let (listener, local_addr) = {
                let listener = TcpListener::bind(addr.to_socket_addrs())
                    .await
                    .context("unable to bind `TcpListener`")?;
                let local_addr = listener.local_addr()?;
                (listener, local_addr)
            };
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
            let server: sync::tcp::Server<
                PolicyEngine<DefaultEngine, Store>,
                LinearStorageProvider<FileManager>,
            > = TestServer::new(Arc::clone(&aranya), listener);
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
                    .aranya
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
        let team = TestTeam::new(&clients);
        let owner = team.owner;
        let admin = team.admin;
        let operator = team.operator;
        let membera = team.membera;
        let memberb = team.memberb;

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

        Ok(clients)
    }
}
