use std::{collections::BTreeMap, io, path::Path, sync::Arc};

use anyhow::{Context, Result};
use aranya_crypto::{
    default::DefaultEngine,
    import::Import,
    keys::SecretKey,
    keystore::{fs_keystore::Store, KeyStore, KeyStoreExt},
    Engine, Rng,
};
use aranya_daemon_api::CS;
use aranya_keygen::{KeyBundle, PublicKeys};
use aranya_runtime::{
    storage::linear::{libc::FileManager, LinearStorageProvider},
    ClientState, StorageProvider,
};
use aranya_util::Addr;
use bimap::BiBTreeMap;
use buggy::BugExt;
use ciborium as cbor;
use serde::{de::DeserializeOwned, Serialize};
use tokio::{fs, sync::Mutex, task::JoinSet};
use tracing::{error, info, info_span, Instrument as _};

use crate::{
    actions::Actions,
    api::{ApiKey, DaemonApiServer, PublicApiKey},
    aqc::Aqc,
    aranya,
    config::Config,
    keystore::{AranyaStore, LocalStore},
    policy,
    sync::task::{quic::State as QuicSyncState, Syncer},
    vm_policy::{PolicyEngine, TEST_POLICY_1},
};

// Use short names so that we can more easily add generics.
/// CE = Crypto Engine
pub(crate) type CE = DefaultEngine;
/// KS = Key Store
pub(crate) type KS = Store;
/// EN = Engine (Policy)
pub(crate) type EN = PolicyEngine<CE, KS>;
/// SP = Storage Provider
pub(crate) type SP = LinearStorageProvider<FileManager>;
/// EF = Policy Effect
pub(crate) type EF = policy::Effect;

pub(crate) type Client = aranya::Client<EN, SP, CE>;
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

    /// Returns the daemon's public API key.
    pub async fn public_api_key(self) -> Result<PublicApiKey<CS>> {
        self.setup_env().await?;

        let mut eng = self.load_crypto_engine().await?;
        let mut store = self.load_local_keystore().await?;
        let sk = self.load_or_gen_api_sk(&mut eng, &mut store).await?;
        sk.public().map_err(Into::into)
    }

    /// The daemon's entrypoint.
    pub async fn run(self) -> Result<()> {
        // Setup environment for daemon's working directory.
        // E.g. creating subdirectories.
        self.setup_env().await?;

        let mut set = JoinSet::new();

        let mut aranya_store = self.load_aranya_keystore().await?;
        let mut eng = self.load_crypto_engine().await?;
        let pk = self
            .load_or_gen_public_keys(&mut eng, &mut aranya_store)
            .await?;

        let mut local_store = self.load_local_keystore().await?;
        let api_sk = self.load_or_gen_api_sk(&mut eng, &mut local_store).await?;

        // Initialize Aranya syncer client.
        let (client, local_addr) = {
            let (client, server) = self
                .setup_aranya(
                    eng.clone(),
                    aranya_store
                        .try_clone()
                        .context("unable to clone keystore")?,
                    &pk,
                    self.cfg.sync_addr,
                )
                .await?;
            let local_addr = server.local_addr()?;
            set.spawn(async move { server.serve().await });

            (client, local_addr)
        };

        // Sync in the background at some specified interval.
        let (send_effects, recv_effects) = tokio::sync::mpsc::channel(256);
        let (mut syncer, peers) = Syncer::new(client.clone(), send_effects, QuicSyncState::new()?);
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
            Aqc::new(eng, pk.ident_pk.id()?, aranya_store, peers)
        };

        let api = DaemonApiServer::new(
            client,
            local_addr,
            self.cfg.uds_api_path.clone(),
            api_sk,
            pk,
            peers,
            recv_effects,
            aqc,
        )?;
        api.serve().await?;

        Ok(())
    }

    /// Initializes the environment (creates directories, etc.).
    async fn setup_env(&self) -> Result<()> {
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

    /// Creates the Aranya client and server.
    async fn setup_aranya(
        &self,
        eng: CE,
        store: AranyaStore<KS>,
        pk: &PublicKeys<CS>,
        external_sync_addr: Addr,
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

        let server = {
            info!(addr = %external_sync_addr, "starting QUIC sync server");
            SyncServer::new(Arc::clone(&aranya), &external_sync_addr)
                .await
                .context("unable to initialize QUIC sync server")?
        };

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

    /// Loads or generates the [`ApiKey`].
    async fn load_or_gen_api_sk<E, S>(
        &self,
        eng: &mut E,
        store: &mut LocalStore<S>,
    ) -> Result<ApiKey<E::CS>>
    where
        E: Engine,
        S: KeyStore,
    {
        let path = self.cfg.daemon_api_pk_path();
        match try_read_cbor::<PublicApiKey<E::CS>>(&path).await? {
            Some(pk) => {
                let id = pk.id()?;
                let sk = store
                    .get_key::<E, ApiKey<E::CS>>(eng, id.into())?
                    // If the public API key exists then the
                    // secret half should exist the keystore. If
                    // not, then something deleted it from the
                    // keystore.
                    .assume("`ApiKey` should exist")?;
                Ok(sk)
            }
            None => {
                let sk = ApiKey::generate(eng, store).context("unable to generate `ApiKey`")?;
                info!("generated `ApiKey`");
                write_cbor(&path, &sk.public()?)
                    .await
                    .context("unable to write `PublicApiKey` to disk")?;
                Ok(sk)
            }
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.cfg.uds_api_path);
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
    use crate::config::AfcConfig;

    /// Tests running the daemon.
    #[test(tokio::test)]
    async fn test_daemon_run() {
        let dir = tempdir().expect("should be able to create temp dir");
        let work_dir = dir.path().join("work");

        let any = Addr::new("localhost", 0).expect("should be able to create new Addr");
        let cfg = Config {
            name: "name".to_string(),
            work_dir: work_dir.clone(),
            uds_api_path: work_dir.join("api"),
            pid_file: work_dir.join("pid"),
            sync_addr: any,
            afc: Some(AfcConfig {
                shm_path: "/test_daemon1".to_owned(),
                unlink_on_startup: true,
                unlink_at_exit: true,
                create: true,
                max_chans: 100,
            }),
            aqc: None,
        };

        let daemon = Daemon::load(cfg)
            .await
            .expect("should be able to load `Daemon`");

        time::timeout(Duration::from_secs(1), daemon.run())
            .await
            .expect_err("`Timeout` should return Elapsed");
    }
}
