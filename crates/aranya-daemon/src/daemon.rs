use std::{collections::BTreeMap, io, path::Path, sync::Arc};

use anyhow::{Context, Result};
use aranya_crypto::{
    default::DefaultEngine,
    import::Import,
    keys::SecretKey,
    keystore::{fs_keystore::Store, KeyStore},
    Engine, Rng,
};
use aranya_keygen::{KeyBundle, PublicKeys};
use aranya_runtime::{
    storage::linear::{libc::FileManager, LinearStorageProvider},
    ClientState, StorageProvider,
};
use aranya_util::Addr;
use bimap::BiBTreeMap;
use ciborium as cbor;
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    fs,
    sync::{broadcast::Receiver, Mutex},
    task::JoinSet,
};
use tracing::{error, info, info_span, Instrument as _};

use crate::{
    actions::Actions,
    api::{ApiKey, DaemonApiServer, PublicApiKey, QSData},
    aqc::Aqc,
    aranya,
    config::Config,
    keystore::{AranyaStore, LocalStore},
    policy,
    sync::task::{
        quic::{Msg, State as QuicSyncState, TeamIdPSKPair},
        Syncer,
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

/// The daemon itself.
pub struct Daemon {
    cfg: Config,
}

impl Daemon {
    /// Loads a `Daemon` using its config.
    pub async fn load(cfg: Config) -> Result<Self> {
        Ok(Self { cfg })
    }

    /// The daemon's entrypoint.
    pub async fn run(self) -> Result<()> {
        // Setup environment for daemon's working directory.
        // E.g. creating subdirectories.
        self.setup_env().await?;

        let mut set = JoinSet::new();

        let mut aranya_store = self.load_aranya_keystore().await?;
        let mut eng = self.load_crypto_engine().await?;
        let pks = self
            .load_or_gen_public_keys(&mut eng, &mut aranya_store)
            .await?;

        let mut local_store = self.load_local_keystore().await?;

        // Generate a fresh API key at startup.
        let api_sk = ApiKey::generate(&mut eng);

        let (psk_send, psk_recv) = tokio::sync::broadcast::channel(16);

        let initial_keys = load_team_psk_pairs(
            &mut eng,
            &mut local_store,
            &SeedDir::new(&self.cfg.seed_id_path()).await?,
        )
        .await?;

        // Initialize the Aranya client and sync server.
        let (client, local_addr) = {
            let (client, server) = self
                .setup_aranya(
                    eng.clone(),
                    aranya_store
                        .try_clone()
                        .context("unable to clone keystore")?,
                    &pks,
                    self.cfg.sync_addr,
                    psk_send.subscribe(),
                    initial_keys.clone(),
                )
                .await?;
            let local_addr = server.local_addr()?;
            set.spawn(async move { server.serve().await });

            (client, local_addr)
        };

        // Sync in the background at some specified interval.
        let (send_effects, recv_effects) = tokio::sync::mpsc::channel(256);

        let state = QuicSyncState::new(initial_keys, psk_recv)?;
        let (mut syncer, peers) = Syncer::new(client.clone(), send_effects, state);
        set.spawn(async move {
            loop {
                if let Err(err) = syncer.next().await {
                    error!(err = ?err, "client unable to sync with peer");
                }
            }
        });

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
            Aqc::new(eng.clone(), pks.ident_pk.id()?, aranya_store, peers)
        };

        // TODO: Fix this when other syncer types are supported
        let Some(_qs_config) = &self.cfg.quic_sync else {
            anyhow::bail!("Supply a valid QUIC sync config")
        };

        let uds_sock = self.cfg.uds_api_sock().clone();
        let pk_path = self.cfg.api_pk_path();
        let seed_id_path = self.cfg.seed_id_path();

        let data = QSData {
            psk_send,
            store: local_store,
            engine: eng,
            seed_id_path,
        };
        let api = DaemonApiServer::new(
            client,
            local_addr,
            uds_sock,
            pk_path,
            api_sk,
            pks,
            peers,
            recv_effects,
            aqc,
            Some(data),
        )?;
        api.serve().await?;

        Ok(())
    }

    /// Initializes the environment (creates directories, etc.).
    async fn setup_env(&self) -> Result<()> {
        // These directories need to already exist.
        for dir in &[
            &self.cfg.runtime_dir,
            &self.cfg.state_dir,
            &self.cfg.cache_dir,
            &self.cfg.logs_dir,
            &self.cfg.config_dir,
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
            ("keystore", self.cfg.keystore_path()),
            ("storage", self.cfg.storage_path()),
        ] {
            aranya_util::create_dir_all(&path)
                .await
                .with_context(|| format!("unable to create '{name}' directory"))?;
        }
        info!("created directories");

        info!("set up environment");
        Ok(())
    }

    /// Creates the Aranya client and sync server.
    async fn setup_aranya(
        &self,
        eng: CE,
        store: AranyaStore<KS>,
        pk: &PublicKeys<CS>,
        external_sync_addr: Addr,
        recv: Receiver<Msg>,
        initial_keys: Vec<TeamIdPSKPair>,
    ) -> Result<(Client, SyncServer)> {
        let device_id = pk.ident_pk.id()?;

        let aranya = Arc::new(Mutex::new(ClientState::new(
            EN::new(TEST_POLICY_1, eng, store, device_id)?,
            SP::new(
                FileManager::new(self.cfg.storage_path())
                    .context("unable to create `FileManager`")?,
            ),
        )));

        let client = Client::new(Arc::clone(&aranya));

        // TODO: Fix this when other syncer types are supported
        let Some(_qs_config) = &self.cfg.quic_sync else {
            anyhow::bail!("Supply a valid QUIC sync config")
        };

        info!(addr = %external_sync_addr, "starting QUIC sync server");
        let server = SyncServer::new(client.clone(), &external_sync_addr, initial_keys, recv)
            .await
            .context("unable to initialize QUIC sync server")?;

        info!(device_id = %device_id, "set up Aranya");

        Ok((client, server))
    }

    /// Loads the crypto engine.
    async fn load_crypto_engine(&self) -> Result<CE> {
        let key = load_or_gen_key(self.cfg.key_wrap_key_path()).await?;
        Ok(CE::new(&key, Rng))
    }

    /// Loads the Aranya keystore.
    ///
    /// The Aranaya keystore contains Aranya's key material.
    async fn load_aranya_keystore(&self) -> Result<AranyaStore<KS>> {
        let dir = self.cfg.aranya_keystore_path();
        aranya_util::create_dir_all(&dir).await?;
        KS::open(&dir)
            .context("unable to open Aranya keystore")
            .map(AranyaStore::new)
    }

    /// Loads the local keystore.
    ///
    /// The local keystore contains key material for the daemon.
    /// E.g., its API key.
    async fn load_local_keystore(&self) -> Result<LocalStore<KS>> {
        let dir = self.cfg.local_keystore_path();
        aranya_util::create_dir_all(&dir).await?;
        KS::open(&dir)
            .context("unable to open local keystore")
            .map(LocalStore::new)
    }

    /// Loads the daemon's [`PublicKeys`].
    async fn load_or_gen_public_keys<E, S>(
        &self,
        eng: &mut E,
        store: &mut AranyaStore<S>,
    ) -> Result<PublicKeys<E::CS>>
    where
        E: Engine,
        S: KeyStore,
    {
        let path = self.cfg.key_bundle_path();
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

    /// Loads the daemmon's public API key.
    ///
    /// For testing purposes only.
    pub async fn load_api_pk(path: &Path) -> Result<Vec<u8>> {
        let pk = try_read_cbor::<PublicApiKey<CS>>(&path)
            .await?
            .context("`PublicApiKey` not found")?;
        pk.encode()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        use std::fs;

        let _ = fs::remove_file(self.cfg.api_pk_path());
        let _ = fs::remove_file(self.cfg.uds_api_sock());
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
    pub async fn load_or_gen_key_inner<K: SecretKey>(path: &Path) -> Result<K> {
        match fs::read(&path).await {
            Ok(buf) => {
                tracing::info!("loading key");
                let key =
                    Import::import(buf.as_slice()).context("unable to import key from file")?;
                Ok(key)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                tracing::info!("generating key");
                let key = K::new(&mut Rng);
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

    use tempfile::tempdir;
    use test_log::test;
    use tokio::time;

    use super::*;
    use crate::config::{AfcConfig, QSConfig};

    /// Tests running the daemon.
    #[test(tokio::test)]
    async fn test_daemon_run() {
        let dir = tempdir().expect("should be able to create temp dir");
        let work_dir = dir.path().join("work");

        let any = Addr::new("localhost", 0).expect("should be able to create new Addr");
        let cfg = Config {
            name: "name".to_string(),
            runtime_dir: work_dir.join("run"),
            state_dir: work_dir.join("state"),
            cache_dir: work_dir.join("cache"),
            logs_dir: work_dir.join("logs"),
            config_dir: work_dir.join("config"),
            sync_addr: any,
            quic_sync: Some(QSConfig {}),
            afc: Some(AfcConfig {
                shm_path: "/test_daemon1".to_owned(),
                unlink_on_startup: true,
                unlink_at_exit: true,
                create: true,
                max_chans: 100,
            }),
            aqc: None,
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

        time::timeout(Duration::from_secs(1), daemon.run())
            .await
            .expect_err("`Timeout` should return Elapsed");
    }
}
