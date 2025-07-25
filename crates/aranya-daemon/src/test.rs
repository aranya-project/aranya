//! Test module for aranya-daemon.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    rust_2018_idioms
)]

use std::{
    collections::BTreeMap,
    fs,
    net::Ipv4Addr,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use aranya_crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    keystore::fs_keystore::Store,
    Csprng, Rng,
};
use aranya_daemon_api::TeamId;
use aranya_keygen::{KeyBundle, PublicKeys};
use aranya_runtime::{
    storage::linear::{libc::FileManager, LinearStorageProvider},
    ClientState, GraphId,
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
    policy::{Effect, KeyBundle as DeviceKeyBundle, Role},
    sync::{
        self,
        task::{quic::PskStore, PeerCacheKey, PeerCacheMap, SyncPeer},
    },
    vm_policy::{PolicyEngine, TEST_POLICY_1},
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
                    TEST_POLICY_1,
                    eng,
                    store.try_clone().context("unable to clone keystore")?,
                    bundle.device_id,
                )?,
                LinearStorageProvider::new(FileManager::new(&storage_dir)?),
            );

            let aranya = Arc::new(Mutex::new(graph));
            let client = TestClient::new(Arc::clone(&aranya));
            let local_addr = Addr::from((Ipv4Addr::LOCALHOST, 0));
            let (psk_store, active_team_rx) = PskStore::new([]);
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
                active_team_rx,
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
        admin.sync_expect(owner, Some(3)).await?;

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
            .add_member(DeviceKeyBundle::try_from(&operator.pk)?)
            .await
            .context("unable to add operator member")?;
        owner
            .actions()
            .assign_role(operator.pk.ident_pk.id()?, Role::Operator)
            .await
            .context("unable to elevate operator role")?;
        operator.sync_expect(owner, Some(5)).await?;

        let operator_caches = operator.syncer.get_peer_caches();
        let operator_cache_size = operator_caches
            .lock()
            .await
            .get(&owner_key)
            .unwrap()
            .heads()
            .len();
        assert!(operator_cache_size > 0);

        operator
            .actions()
            .add_member(DeviceKeyBundle::try_from(&membera.pk)?)
            .await
            .context("unable to add membera member")?;
        membera.sync_expect(admin, Some(3)).await?;
        operator
            .actions()
            .add_member(DeviceKeyBundle::try_from(&memberb.pk)?)
            .await
            .context("unable to add memberb member")?;
        memberb.sync_expect(admin, Some(3)).await?;

        owner.sync_expect(operator, Some(2)).await?;
        admin.sync_expect(operator, Some(5)).await?;
        membera.sync_expect(operator, Some(5)).await?;
        memberb.sync_expect(operator, Some(5)).await?;

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
