use std::{io, net::SocketAddr, path::Path, sync::Arc};

use anyhow::{anyhow, bail, Context, Result};
use aps::memory::State as MemoryState;
use ciborium as cbor;
use crypto::{
    aead::Aead,
    default::{DefaultCipherSuite, DefaultEngine},
    generic_array::GenericArray,
    import::Import,
    keys::SecretKeyBytes,
    keystore::fs_keystore::Store,
    CipherSuite, Random, Rng,
};
use keygen::{KeyBundle, PublicKeys};
use runtime::{
    storage::linear::{libc::FileManager, LinearStorageProvider},
    ClientState,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{fs, net::TcpListener, sync::Mutex, task::JoinSet};
use tracing::{error, info};

use crate::{
    addr::Addr,
    api::DaemonApiServer,
    aranya,
    config::Config,
    policy,
    sync::Syncer,
    util,
    vm_policy::{PolicyEngine, TEST_POLICY_1},
};

// Use short names so that we can more easily add generics.
// CE = Crypto Engine
// CS = Cipher Suite
// KS = Key Store
// EN = Engine (Policy)
// SP = Storage Providers
pub(crate) type CE = DefaultEngine;
pub(crate) type CS = DefaultCipherSuite;
pub(crate) type KS = Store;
pub(crate) type EN = PolicyEngine<CE, KS>;
pub(crate) type SP = LinearStorageProvider<FileManager>;
pub(crate) type EF = policy::Effect;

pub(crate) type Client = aranya::Client<EN, SP, CE>;
type Server = aranya::Server<EN, SP>;
type KeyWrapKeyBytes = SecretKeyBytes<<<CS as CipherSuite>::Aead as Aead>::KeySize>;
type KeyWrapKey = <<CS as CipherSuite>::Aead as Aead>::Key;

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

        // Load keys from the keystore or generate new ones if there are no existing keys.
        let mut store = KS::open(self.cfg.keystore_path()).context("unable to open keystore")?;
        let mut eng = {
            let key = self.load_or_gen_key_wrap_key().await?;
            CE::new(&key, Rng)
        };
        let pk = self.load_or_gen_public_keys(&mut eng, &mut store).await?;

        // Initialize Aranya client.
        let client = {
            let (client, server) = self
                .setup_aranya(
                    eng.clone(),
                    store.try_clone().context("unable to clone keystore")?,
                    &pk,
                    self.cfg.sync_addr,
                )
                .await?;
            let client = Arc::new(client);
            set.spawn(async move { server.serve().await });

            client
        };

        // Sync in the background at some specified interval.
        // Effects are sent to `Api` via `mux`.
        let (mut syncer, peers) = Syncer::new(Arc::clone(&client));
        set.spawn(async move {
            loop {
                if let Err(err) = syncer.next().await {
                    error!(err = ?err, "unable to sync with peer");
                }
            }
        });

        // TODO: have Aranya write to shm.
        let aps = self.setup_aps()?;

        // TODO: add context to error.
        let api = DaemonApiServer::new(
            client,
            aps,
            self.cfg.uds_api_path.clone(),
            Arc::new(pk),
            peers,
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
            util::create_dir_all(&path)
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
        store: KS,
        pk: &PublicKeys<CS>,
        external_sync_addr: Addr,
    ) -> Result<(Client, Server)> {
        let user_id = pk.ident_pk.id()?;

        let aranya = Arc::new(Mutex::new(ClientState::new(
            EN::new(TEST_POLICY_1, eng, store, user_id)?,
            SP::new(
                FileManager::new(self.cfg.storage_path())
                    .context("unable to create `FileManager`")?,
            ),
        )));

        let client = Client::new(Arc::clone(&aranya));

        let server = {
            info!(addr = %external_sync_addr, "starting TCP server");
            let listener = TcpListener::bind(SocketAddr::V4(external_sync_addr.lookup().await?))
                .await
                .context("unable to bind TCP listener")?;
            Server::new(Arc::clone(&aranya), listener)
        };

        info!(user_id = %user_id, "set up Aranya");

        Ok((client, server))
    }

    /// Creates APS shm.
    fn setup_aps(&self) -> Result<MemoryState<CS>> {
        // TODO: issue stellar-tapestry#34
        // add aps::shm{ReadState, WriteState} back in after linux/arm64 bugfix
        let write = MemoryState::<CS>::new();

        Ok(write)
    }

    /// Loads the [`KeyBundle`].
    async fn load_or_gen_public_keys(
        &self,
        eng: &mut CE,
        store: &mut KS,
    ) -> Result<PublicKeys<CS>> {
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

    /// Loads the key wrapping key used by [`CryptoEngine`].
    async fn load_or_gen_key_wrap_key(&self) -> Result<KeyWrapKey> {
        let path = self.cfg.key_wrap_key_path();
        let (bytes, loaded) = match fs::read(&path).await {
            Ok(buf) => {
                info!("loaded key wrap key");
                let bytes = KeyWrapKeyBytes::new(
                    *GenericArray::try_from_slice(&buf)
                        .map_err(|_| anyhow!("invalid key wrap key length"))?,
                );
                (bytes, true)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                info!("generating key wrap key");
                let bytes = KeyWrapKeyBytes::random(&mut Rng);
                (bytes, false)
            }
            Err(err) => bail!("unable to read key wrap key: {err}"),
        };

        // Import before writing in case importing fails.
        let key = Import::import(bytes.as_bytes()).context("unable to import new key wrap key")?;
        if !loaded {
            util::write_file(&path, bytes.as_bytes())
                .await
                .context("unable to write key wrap key")?;
        }
        Ok(key)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // TODO: issue stellar-tapestry#34 shm unlink
        let _ = std::fs::remove_file(&self.cfg.uds_api_path);
    }
}

/// Tries to read JSON from `path`.
async fn try_read_cbor<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<Option<T>> {
    match fs::read(path.as_ref()).await {
        Ok(buf) => Ok(cbor::from_reader(&buf[..])?),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Writes `data` as JSON to `path`.
async fn write_cbor(path: impl AsRef<Path>, data: impl Serialize) -> Result<()> {
    let mut buf = Vec::new();
    cbor::into_writer(&data, &mut buf)?;
    Ok(util::write_file(path, &buf).await?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

    use std::time::Duration;

    use tempfile::tempdir;
    use test_log::test;
    use tokio::time;

    use super::*;

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
        };

        let daemon = Daemon::load(cfg)
            .await
            .expect("should be able to load `Daemon`");

        time::timeout(Duration::from_secs(1), daemon.run())
            .await
            .expect_err("`Timeout` should return Elapsed");
    }
}
