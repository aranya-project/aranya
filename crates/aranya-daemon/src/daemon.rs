use std::{collections::BTreeMap, io, path::Path, sync::Arc};

use anyhow::{Context, Result};
use aranya_crypto::{
    dangerous::spideroak_crypto::{import::Import, keys::SecretKey},
    default::DefaultEngine,
    keystore::{fs_keystore::Store, KeyStore},
    Engine, Rng,
};
use aranya_keygen::{KeyBundle, PublicKeys};
use aranya_runtime::{
    storage::linear::{libc::FileManager, LinearStorageProvider},
    ClientState, StorageProvider,
};
use aranya_util::ready;
use bimap::BiBTreeMap;
use buggy::{bug, Bug, BugExt};
use ciborium as cbor;
use serde::{de::DeserializeOwned, Serialize};
use tokio::{fs, sync::Mutex, task::JoinSet};
use tracing::{error, info, info_span, Instrument as _};

use crate::{
    actions::Actions,
    api::{ApiKey, DaemonApiServer, EffectReceiver, QSData},
    aqc::Aqc,
    aranya,
    config::{Config, Toggle},
    keystore::{AranyaStore, LocalStore},
    policy,
    sync::task::{
        quic::{PskStore, State as QuicSyncClientState, SyncParams},
        PeerCacheMap, SyncPeers, Syncer,
    },
    util::{load_team_psk_pairs, SeedDir},
    vm_policy::{PolicyEngine, TEST_POLICY_1},
};

// Use short names so that we can more easily add generics.
/// CE = Crypto Engine
pub(crate) type CE = DefaultEngine;
/// CS = Crypto Suite
pub(crate) type CS = <DefaultEngine as Engine>::CS;
/// KS = Key Store
pub(crate) type KS = Store;
/// EN = Engine (Policy)
pub(crate) type EN = PolicyEngine<CE, KS>;
/// SP = Storage Provider
pub(crate) type SP = LinearStorageProvider<FileManager>;
/// EF = Policy Effect
pub(crate) type EF = policy::Effect;

pub(crate) type Client = aranya::Client<EN, SP>;
pub(crate) type SyncServer = crate::sync::task::quic::Server<EN, SP>;

mod invalid_graphs {
    use std::{
        collections::HashSet,
        sync::{Arc, RwLock},
    };

    use aranya_runtime::GraphId;

    /// Keeps track of which graphs have had a finalization error.
    ///
    /// Once a finalization error has occurred for a graph,
    /// the graph error is permanent.
    /// The API will prevent subsequent operations on the invalid graph.
    #[derive(Clone, Debug, Default)]
    pub(crate) struct InvalidGraphs {
        // NB: Since the locking is short and not held over await points,
        // we use a standard rwlock instead of tokio's.
        map: Arc<RwLock<HashSet<GraphId>>>,
    }

    impl InvalidGraphs {
        pub fn insert(&self, graph_id: GraphId) {
            #[allow(clippy::expect_used)]
            self.map.write().expect("poisoned").insert(graph_id);
        }

        pub fn contains(&self, graph_id: GraphId) -> bool {
            #[allow(clippy::expect_used)]
            self.map.read().expect("poisoned").contains(&graph_id)
        }
    }
}
pub(crate) use invalid_graphs::InvalidGraphs;

/// Handle for the spawned daemon.
///
/// Dropping this will abort the daemon's tasks.
#[clippy::has_significant_drop]
#[derive(Debug)]
pub struct DaemonHandle {
    set: JoinSet<()>,
}

impl DaemonHandle {
    /// Wait for the daemon to finish.
    ///
    /// Panics if any of the daemon's tasks panic.
    pub async fn join(mut self) -> Result<(), Bug> {
        match self.set.join_next().await.assume("set not empty")? {
            Ok(()) => {}
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(err) => {
                error!(error = %err, "tasks unexpectedly cancelled");
                bug!("tasks cancelled");
            }
        }
        self.set.abort_all();
        Ok(())
    }
}

/// The daemon itself.
#[derive(Debug)]
pub struct Daemon {
    sync_server: SyncServer,
    syncer: Syncer<QuicSyncClientState>,
    api: DaemonApiServer,
    span: tracing::Span,
}

impl Daemon {
    /// Loads a `Daemon` using its config.
    pub async fn load(cfg: Config) -> Result<Self> {
        let name = (!cfg.name.is_empty()).then_some(cfg.name.as_str());
        let span = info_span!("daemon", name);
        let span_id = span.id();

        async move {
            // TODO: Fix this when other syncer types are supported
            let Toggle::Enabled(qs_config) = &cfg.sync.quic else {
                anyhow::bail!("Supply a valid QUIC sync config")
            };

            // TODO: Make aqc optional.
            let Toggle::Enabled(_) = &cfg.aqc else {
                anyhow::bail!(
                    "AQC is currently required, set `aqc.enable = true` in daemon config."
                )
            };

            Self::setup_env(&cfg).await?;
            let mut aranya_store = Self::load_aranya_keystore(&cfg).await?;
            let mut eng = Self::load_crypto_engine(&cfg).await?;
            let pks = Self::load_or_gen_public_keys(&cfg, &mut eng, &mut aranya_store).await?;

            let mut local_store = Self::load_local_keystore(&cfg).await?;

            // Generate a fresh API key at startup.
            let api_sk = ApiKey::generate(&mut eng);
            aranya_util::write_file(cfg.api_pk_path(), &api_sk.public()?.encode()?)
                .await
                .context("unable to write API public key")?;
            info!(path = %cfg.api_pk_path().display(), "wrote API public key");

            // Initialize the PSK store used by the syncer and sync server
            let seed_id_dir = SeedDir::new(cfg.seed_id_path().to_path_buf()).await?;
            let initial_keys =
                load_team_psk_pairs(&mut eng, &mut local_store, &seed_id_dir).await?;
            let psk_store = Arc::new(PskStore::new(initial_keys));

            let invalid_graphs = InvalidGraphs::default();

            // Create a shared PeerCacheMap
            let caches: PeerCacheMap = Arc::new(Mutex::new(BTreeMap::new()));

            // Initialize Aranya client, sync client,and sync server.
            let (client, sync_server, syncer, peers, recv_effects) = Self::setup_aranya(
                &cfg,
                eng.clone(),
                aranya_store
                    .try_clone()
                    .context("unable to clone keystore")?,
                &pks,
                SyncParams {
                    psk_store: Arc::clone(&psk_store),
                    caches: caches.clone(),
                    server_addr: qs_config.addr,
                },
                invalid_graphs.clone(),
            )
            .await?;
            let local_addr = sync_server.local_addr()?;

            let graph_ids = client
                .aranya
                .lock()
                .await
                .provider()
                .list_graph_ids()?
                .flatten()
                .collect::<Vec<_>>();

            let aqc = {
                let peers = {
                    let mut peers = BTreeMap::new();
                    for graph_id in &graph_ids {
                        let graph_peers = BiBTreeMap::from_iter(
                            client
                                .actions(graph_id)
                                .query_aqc_network_names_off_graph()
                                .await?,
                        );
                        peers.insert(*graph_id, graph_peers);
                    }
                    peers
                };
                Aqc::new(
                    eng.clone(),
                    pks.ident_pk.id()?,
                    aranya_store
                        .try_clone()
                        .context("unable to clone keystore")?,
                    peers,
                )
            };

            #[cfg(all(feature = "afc", feature = "unstable"))]
            let afc = {
                let peers = {
                    let mut peers = BTreeMap::new();
                    for graph_id in &graph_ids {
                        let graph_peers = BiBTreeMap::from_iter(
                            client
                                .actions(graph_id)
                                .query_afc_network_names_off_graph()
                                .await?,
                        );
                        peers.insert(*graph_id, graph_peers);
                    }
                    peers
                };
                // TODO: use AFC shm key store
                Aqc::new(
                    eng.clone(),
                    pks.ident_pk.id()?,
                    aranya_store
                        .try_clone()
                        .context("unable to clone keystore")?,
                    peers,
                )
            };

            let data = QSData { psk_store };

            let crypto = crate::api::Crypto {
                engine: eng,
                local_store,
                aranya_store,
            };

            let api = DaemonApiServer::new(
                client,
                local_addr,
                cfg.uds_api_sock(),
                api_sk,
                pks,
                peers,
                recv_effects,
                invalid_graphs,
                aqc,
                #[cfg(all(feature = "afc", feature = "unstable"))]
                afc,
                crypto,
                seed_id_dir,
                Some(data),
            )?;
            Ok(Self {
                sync_server,
                syncer,
                api,
                span,
            })
        }
        .instrument(info_span!(parent: span_id, "load"))
        .await
    }

    /// The daemon's entrypoint.
    pub async fn spawn(self) -> Result<DaemonHandle, ready::WaitError> {
        let _guard = self.span.enter();
        let mut set = JoinSet::new();
        let waiter = ready::Waiter::new(3);
        set.spawn(
            self.sync_server
                .serve(waiter.notifier())
                .instrument(info_span!("sync-server")),
        );
        set.spawn({
            self.syncer
                .run(waiter.notifier())
                .instrument(info_span!("syncer"))
        });
        set.spawn(
            self.api
                .serve(waiter.notifier())
                .instrument(info_span!("api-server")),
        );
        waiter.wait().await?;
        Ok(DaemonHandle { set })
    }

    /// Initializes the environment (creates directories, etc.).
    async fn setup_env(cfg: &Config) -> Result<()> {
        // These directories need to already exist.
        for dir in &[
            &cfg.runtime_dir,
            &cfg.state_dir,
            &cfg.cache_dir,
            &cfg.logs_dir,
            &cfg.config_dir,
        ] {
            if !dir.try_exists()? {
                return Err(anyhow::anyhow!(
                    "directory does not exist: {}",
                    dir.display()
                ));
            }
        }

        // These directories aren't created for us.
        for (name, path) in [
            ("keystore", cfg.keystore_path()),
            ("storage", cfg.storage_path()),
        ] {
            aranya_util::create_dir_all(&path)
                .await
                .with_context(|| format!("unable to create '{name}' directory"))?;
        }
        info!("created directories");

        // Remove unix socket so we can re-bind after e.g. the process is killed.
        // (We could remove it at exit but can't guarantee that will happen.)
        let uds_api_sock = cfg.uds_api_sock();
        if let Err(err) = fs::remove_file(&uds_api_sock).await {
            if err.kind() != io::ErrorKind::NotFound {
                return Err(err).context(format!("unable to remove api socket {uds_api_sock:?}"));
            }
        }

        info!("set up environment");
        Ok(())
    }

    /// Creates the Aranya client, sync client, and sync server.
    async fn setup_aranya(
        cfg: &Config,
        eng: CE,
        store: AranyaStore<KS>,
        pk: &PublicKeys<CS>,
        SyncParams {
            psk_store,
            caches,
            server_addr,
        }: SyncParams,
        invalid_graphs: InvalidGraphs,
    ) -> Result<(
        Client,
        SyncServer,
        Syncer<QuicSyncClientState>,
        SyncPeers,
        EffectReceiver,
    )> {
        let device_id = pk.ident_pk.id()?;

        let aranya = Arc::new(Mutex::new(ClientState::new(
            EN::new(TEST_POLICY_1, eng, store, device_id)?,
            SP::new(
                FileManager::new(cfg.storage_path()).context("unable to create `FileManager`")?,
            ),
        )));

        let client = Client::new(Arc::clone(&aranya));

        // Sync in the background at some specified interval.
        let (send_effects, recv_effects) = tokio::sync::mpsc::channel(256);

        // Initialize the syncer
        let (syncer, peers, conns, conn_rx) = Syncer::new(
            client.clone(),
            send_effects,
            invalid_graphs,
            Arc::clone(&psk_store),
            server_addr,
            Arc::clone(&caches),
        )?;

        info!(addr = %server_addr, "starting QUIC sync server");
        let server = SyncServer::new(
            client.clone(),
            &server_addr,
            psk_store,
            conns,
            conn_rx,
            caches,
        )
        .await
        .context("unable to initialize QUIC sync server")?;

        info!(device_id = %device_id, "set up Aranya");

        Ok((client, server, syncer, peers, recv_effects))
    }

    /// Loads the crypto engine.
    async fn load_crypto_engine(cfg: &Config) -> Result<CE> {
        let key = load_or_gen_key(cfg.key_wrap_key_path()).await?;
        Ok(CE::new(&key, Rng))
    }

    /// Loads the Aranya keystore.
    ///
    /// The Aranaya keystore contains Aranya's key material.
    async fn load_aranya_keystore(cfg: &Config) -> Result<AranyaStore<KS>> {
        let dir = cfg.aranya_keystore_path();
        aranya_util::create_dir_all(&dir).await?;
        KS::open(&dir)
            .context("unable to open Aranya keystore")
            .map(AranyaStore::new)
    }

    /// Loads the local keystore.
    ///
    /// The local keystore contains key material for the daemon.
    /// E.g., its API key.
    async fn load_local_keystore(cfg: &Config) -> Result<LocalStore<KS>> {
        let dir = cfg.local_keystore_path();
        aranya_util::create_dir_all(&dir).await?;
        KS::open(&dir)
            .context("unable to open local keystore")
            .map(LocalStore::new)
    }

    /// Loads the daemon's [`PublicKeys`].
    async fn load_or_gen_public_keys<E, S>(
        cfg: &Config,
        eng: &mut E,
        store: &mut AranyaStore<S>,
    ) -> Result<PublicKeys<E::CS>>
    where
        E: Engine,
        S: KeyStore,
    {
        let path = cfg.key_bundle_path();
        let bundle = match try_read_cbor(&path).await? {
            Some(bundle) => bundle,
            None => {
                let bundle =
                    KeyBundle::generate(eng, store).context("unable to generate key bundle")?;
                info!("generated key bundle");
                write_cbor(&path, &bundle)
                    .await
                    .context("unable to write `KeyBundle` to disk")?;
                bundle
            }
        };
        bundle.public_keys(eng, store)
    }
}

/// Tries to read CBOR from `path`.
async fn try_read_cbor<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<Option<T>> {
    match fs::read(path.as_ref()).await {
        Ok(buf) => Ok(cbor::from_reader(&buf[..])?),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Writes `data` as CBOR to `path`.
async fn write_cbor(path: impl AsRef<Path>, data: impl Serialize) -> Result<()> {
    let mut buf = Vec::new();
    cbor::into_writer(&data, &mut buf)?;
    Ok(aranya_util::write_file(path, &buf).await?)
}

/// Loads a key from a file or generates and writes a new one.
async fn load_or_gen_key<K: SecretKey>(path: impl AsRef<Path>) -> Result<K> {
    async fn load_or_gen_key_inner<K: SecretKey>(path: &Path) -> Result<K> {
        match fs::read(&path).await {
            Ok(buf) => {
                tracing::info!("loading key");
                let key =
                    Import::import(buf.as_slice()).context("unable to import key from file")?;
                Ok(key)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                tracing::info!("generating key");
                let key = K::random(&mut Rng);
                let bytes = key
                    .try_export_secret()
                    .context("unable to export new key")?;
                aranya_util::write_file(&path, bytes.as_bytes())
                    .await
                    .context("unable to write key")?;
                Ok(key)
            }
            Err(err) => Err(err).context("unable to read key"),
        }
    }
    let path = path.as_ref();
    load_or_gen_key_inner(path)
        .instrument(info_span!("load_or_gen_key", ?path))
        .await
        .with_context(|| format!("load_or_gen_key({path:?})"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

    use std::time::Duration;

    use aranya_util::Addr;
    use tempfile::tempdir;
    use test_log::test;
    use tokio::time;

    use super::*;
    use crate::config::{AqcConfig, QuicSyncConfig, SyncConfig, Toggle};

    /// Tests running the daemon.
    #[test(tokio::test)]
    async fn test_daemon_run() {
        let dir = tempdir().expect("should be able to create temp dir");
        let work_dir = dir.path().join("work");

        let any = Addr::new("localhost", 0).expect("should be able to create new Addr");
        let cfg = Config {
            name: "test-daemon-run".into(),
            runtime_dir: work_dir.join("run"),
            state_dir: work_dir.join("state"),
            cache_dir: work_dir.join("cache"),
            logs_dir: work_dir.join("logs"),
            config_dir: work_dir.join("config"),
            sync: SyncConfig {
                quic: Toggle::Enabled(QuicSyncConfig { addr: any }),
            },
            aqc: Toggle::Enabled(AqcConfig {}),
        };
        for dir in [
            &cfg.runtime_dir,
            &cfg.state_dir,
            &cfg.cache_dir,
            &cfg.logs_dir,
            &cfg.config_dir,
        ] {
            aranya_util::create_dir_all(dir)
                .await
                .expect("should be able to create directory");
        }

        let daemon = Daemon::load(cfg)
            .await
            .expect("should be able to load `Daemon`");

        time::timeout(
            Duration::from_secs(1),
            daemon.spawn().await.expect("startup").join(),
        )
        .await
        .expect_err("`Timeout` should return Elapsed");
    }
}
