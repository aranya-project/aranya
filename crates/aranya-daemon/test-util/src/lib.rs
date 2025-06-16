#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::borrow_interior_mutable_const,
    clippy::declare_interior_mutable_const,
    rust_2018_idioms
)]

use std::{
    collections::BTreeMap,
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
        task::quic::{Msg, PeerCacheMap},
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
use s2n_quic::provider::tls::rustls::rustls::crypto::{hash::HashAlgorithm, PresharedKey};
use tempfile::{tempdir, TempDir};
use tokio::{
    sync::{
        broadcast::{self, Receiver as BReceiver, Sender},
        mpsc::{self, Receiver},
        Mutex,
    },
    task::{self, AbortHandle},
};

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
    psk_send: Sender<Msg>,
}

impl TestDevice {
    pub fn new(
        client: TestClient,
        server: TestServer,
        local_addr: Addr,
        pk: PublicKeys<DefaultCipherSuite>,
        graph_id: GraphId,
        psk: (Sender<Msg>, BReceiver<Msg>),
        caches: PeerCacheMap,
    ) -> Result<Self> {
        let server_addr = server.local_addr()?.into();
        let handle = task::spawn(async { server.serve().await }).abort_handle();

        let state = TestState::new([], psk.1.resubscribe(), caches)?;

        let (send, effect_recv) = mpsc::channel(1);
        let (syncer, _sync_peers) = TestSyncer::new(client, send, state, server_addr);
        Ok(Self {
            syncer,
            graph_id,
            local_addr,
            handle,
            pk,
            effect_recv,
            psk_send: psk.0,
        })
    }
}

impl TestDevice {
    pub async fn sync(&mut self, device: &TestDevice) -> Result<Vec<Effect>> {
        self.sync_expect(device, None).await
    }

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
            .sync(&self.graph_id, &device.local_addr)
            .await
            .with_context(|| format!("unable to sync with peer at {}", device.local_addr))?;
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

    /// Syncs with a device twice.
    ///
    /// First sync should receive `must_receive` commands.
    /// Second sync should receive 0 commands. This is to check if the cache is being updated.
    ///
    /// Returns the effects that were received.
    pub async fn sync_check_cache(
        &mut self,
        device: &TestDevice,
        must_receive: Option<usize>,
    ) -> Result<Vec<Effect>> {
        let effects = self.sync_expect(device, must_receive).await?;
        self.sync_expect(device, Some(0)).await?;
        Ok(effects)
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
                self.psk_send.send(Msg::Insert((team_id, psk.clone())))?;

                Ok((graph_id, effects, psk))
            }
            Err(e) => Err(e),
        }
    }

    async fn add_team(&self, psk: Arc<PresharedKey>) -> Result<()> {
        let team_id = TeamId::from(*self.graph_id.as_array());
        self.psk_send.send(Msg::Insert((team_id, psk.clone())))?;

        Ok(())
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

pub struct TestTeam<'a> {
    pub owner: &'a mut TestDevice,
    pub admin: &'a mut TestDevice,
    pub operator: &'a mut TestDevice,
    pub membera: &'a mut TestDevice,
    pub memberb: &'a mut TestDevice,
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

        let (send, rx) = broadcast::channel(16);
        let caches = Arc::new(Mutex::new(BTreeMap::new()));

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
            let server =
                TestServer::new(client.clone(), &addr, [], send.subscribe(), caches.clone())
                    .await?;
            let local_addr = server.local_addr()?;
            (client, server, local_addr, pk)
        };

        TestDevice::new(
            client,
            server,
            local_addr.into(),
            pk,
            id,
            (send, rx),
            caches,
        )
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
        let (mut clients, psk) = self
            .new_group(5)
            .await
            .context("unable to create clients")?;
        let team = TestTeam::new(&mut clients);
        let owner = team.owner;
        let mut admin = team.admin;
        let mut operator = team.operator;
        let mut membera = team.membera;
        let mut memberb = team.memberb;

        for member in [&mut admin, &mut operator, &mut membera, &mut memberb] {
            member.add_team(psk.clone()).await?;
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
        admin.sync_check_cache(owner, Some(3)).await?;
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
        operator.sync_check_cache(owner, Some(5)).await?;
        operator
            .actions()
            .add_member(DeviceKeyBundle::try_from(&membera.pk)?)
            .await
            .context("unable to add membera member")?;
        membera.sync_check_cache(admin, Some(3)).await?;
        operator
            .actions()
            .add_member(DeviceKeyBundle::try_from(&memberb.pk)?)
            .await
            .context("unable to add memberb member")?;
        memberb.sync_check_cache(admin, Some(3)).await?;

        owner.sync_check_cache(operator, Some(2)).await?;
        admin.sync_check_cache(operator, Some(5)).await?;
        membera.sync_check_cache(operator, Some(5)).await?;
        memberb.sync_check_cache(operator, Some(5)).await?;

        Ok(clients)
    }
}
