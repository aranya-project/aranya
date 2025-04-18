#[cfg(feature = "afc")]
use std::str::FromStr;
use std::{io, path::Path, sync::Arc};

use anyhow::{anyhow, bail, Context, Result};
use aranya_crypto::{
    aead::Aead, default::DefaultEngine, generic_array::GenericArray, import::Import,
    keys::SecretKeyBytes, keystore::fs_keystore::Store, CipherSuite, Random, Rng,
};
use aranya_daemon_api::{KeyStoreInfo, CS};
#[cfg(feature = "afc")]
use aranya_fast_channels::shm::{self, Flag, Mode, WriteState};
use aranya_keygen::{KeyBundle, PublicKeys};
use aranya_runtime::{
    storage::linear::{libc::FileManager, LinearStorageProvider},
    ClientState,
};
use aranya_util::Addr;
use ciborium as cbor;
use serde::{de::DeserializeOwned, Serialize};
use tokio::{fs, net::TcpListener, sync::Mutex, task::JoinSet};
#[cfg(feature = "afc")]
use tracing::debug;
use tracing::{error, info};

use crate::{
    api::DaemonApiServer,
    aranya,
    config::Config,
    policy,
    sync::Syncer,
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
        let (client, local_addr) = {
            let (client, server) = self
                .setup_aranya(
                    eng.clone(),
                    store.try_clone().context("unable to clone keystore")?,
                    &pk,
                    self.cfg.sync_addr,
                )
                .await?;
            let local_addr = server.local_addr()?;
            let client = Arc::new(client);
            set.spawn(async move { server.serve().await });

            (client, local_addr)
        };

        // Sync in the background at some specified interval.
        // Effects are sent to `Api` via `mux`.
        let (send_effects, recv_effects) = tokio::sync::mpsc::channel(256);
        let (mut syncer, peers) = Syncer::new(Arc::clone(&client), send_effects);
        set.spawn(async move {
            loop {
                if let Err(err) = syncer.next().await {
                    error!(err = ?err, "unable to sync with peer");
                }
            }
        });

        let api = {
            #[cfg(feature = "afc")]
            {
                let afc = self.setup_afc()?;
                DaemonApiServer::new(
                    client,
                    local_addr,
                    Arc::new(Mutex::new(afc)),
                    eng,
                    KeyStoreInfo {
                        path: self.cfg.keystore_path(),
                        wrapped_key: self.cfg.key_wrap_key_path(),
                    },
                    store,
                    self.cfg.uds_api_path.clone(),
                    Arc::new(pk),
                    peers,
                    recv_effects,
                )
                .context("Unable to start daemon API!")?
            }
            #[cfg(not(feature = "afc"))]
            {
                DaemonApiServer::new(
                    client,
                    local_addr,
                    KeyStoreInfo {
                        path: self.cfg.keystore_path(),
                        wrapped_key: self.cfg.key_wrap_key_path(),
                    },
                    self.cfg.uds_api_path.clone(),
                    Arc::new(pk),
                    peers,
                    recv_effects,
                )
                .context("Unable to start daemon API!")?
            }
        };
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
        store: KS,
        pk: &PublicKeys<CS>,
        external_sync_addr: Addr,
    ) -> Result<(Client, Server)> {
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
            info!(addr = %external_sync_addr, "starting TCP server");
            let listener = TcpListener::bind(external_sync_addr.to_socket_addrs())
                .await
                .context("unable to bind TCP listener")?;
            Server::new(Arc::clone(&aranya), listener)
        };

        info!(device_id = %device_id, "set up Aranya");

        Ok((client, server))
    }

    /// Creates AFC shm.
    #[cfg(feature = "afc")]
    fn setup_afc(&self) -> Result<WriteState<CS, Rng>> {
        // TODO: issue stellar-tapestry#34
        // afc::shm{ReadState, WriteState} doesn't work on linux/arm64
        debug!(
            shm_path = self.cfg.afc.shm_path,
            "setting up afc shm write side"
        );
        let write = {
            let path = aranya_util::ShmPathBuf::from_str(&self.cfg.afc.shm_path)
                .context("unable to parse AFC shared memory path")?;
            if self.cfg.afc.unlink_on_startup && self.cfg.afc.create {
                let _ = shm::unlink(&path);
            }
            WriteState::open(
                &path,
                Flag::Create,
                Mode::ReadWrite,
                self.cfg.afc.max_chans,
                Rng,
            )
            .context("unable to open `WriteState`")?
        };

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
            aranya_util::write_file(&path, bytes.as_bytes())
                .await
                .context("unable to write key wrap key")?;
        }
        Ok(key)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        #[cfg(feature = "afc")]
        if self.cfg.afc.unlink_at_exit {
            if let Ok(path) = aranya_util::util::ShmPathBuf::from_str(&self.cfg.afc.shm_path) {
                let _ = shm::unlink(path);
            }
        }
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
    Ok(aranya_util::write_file(path, &buf).await?)
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
            afc: AfcConfig {
                shm_path: "/test_daemon1".to_owned(),
                unlink_on_startup: true,
                unlink_at_exit: true,
                create: true,
                max_chans: 100,
            },
        };

        let daemon = Daemon::load(cfg)
            .await
            .expect("should be able to load `Daemon`");

        time::timeout(Duration::from_secs(1), daemon.run())
            .await
            .expect_err("`Timeout` should return Elapsed");
    }
}
