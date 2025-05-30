//! PSK setup for rustls for use with QUIC connections

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as SyncMutex},
};

use anyhow::{bail, Result};
use aranya_daemon_api::TeamId;
use aranya_runtime::StorageProvider;
use buggy::BugExt as _;
use s2n_quic::provider::tls::rustls::rustls::{
    client::PresharedKeyStore, crypto::PresharedKey, pki_types::ServerName,
    server::SelectsPresharedKeys,
};
use tokio::sync::mpsc;
use tracing::{debug, error};

use super::AranyaClient;

pub(crate) type TeamIdPSKPair = (TeamId, Arc<PresharedKey>);

#[derive(Debug, Clone)]
/// Insertion and Removal updates.
/// Used by [`ClientPresharedKeys`] and [`ServerPresharedKeys`].
pub enum Msg {
    /// Insertion update
    Insert(TeamIdPSKPair),
    /// Removal update
    Remove(TeamId),
}

#[derive(Debug)]
/// Contains thread-safe references to [PresharedKey]s.
/// Used by [`super::Server`]
pub struct ServerPresharedKeys {
    keys: SyncMutex<HashMap<Vec<u8>, TeamIdPSKPair>>,
    // Optional sender to report the selected identity
    identity_sender: mpsc::Sender<Vec<u8>>,
}

impl ServerPresharedKeys {
    pub(super) fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        // Create the mpsc channel for PSK identities
        let (identity_tx, identity_rx) = mpsc::channel::<Vec<u8>>(10);

        (
            Self {
                keys: SyncMutex::new(HashMap::new()),
                identity_sender: identity_tx,
            },
            identity_rx,
        )
    }

    fn insert(&self, id: TeamId, psk: Arc<PresharedKey>) -> Result<()> {
        match self.keys.lock() {
            Ok(ref mut map) => {
                map.insert(psk.identity().to_vec(), (id, psk));
            }
            Err(e) => bail!(e.to_string()),
        }

        Ok(())
    }

    pub(super) fn extend(&self, psks: impl IntoIterator<Item = TeamIdPSKPair>) -> Result<()> {
        match self.keys.lock() {
            Ok(ref mut keys) => {
                keys.extend(
                    psks.into_iter()
                        .map(|(id, psk)| (psk.identity().to_vec(), (id, psk))),
                );
            }
            Err(e) => bail!(e.to_string()),
        }

        Ok(())
    }

    /// Handle PSK insertion and removal updates.
    pub fn handle_msg(&self, msg: Msg) {
        match msg {
            Msg::Insert((team_id, psk)) => {
                let _ = self
                    .insert(team_id, psk)
                    .inspect_err(|err| error!(err = ?err, "unable to insert PSK"));
            }
            Msg::Remove(_team_id) => {
                todo!("Add remove method to `ServerPreSharedKeys`")
            }
        }
    }
}

impl SelectsPresharedKeys for ServerPresharedKeys {
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        let id_key = self
            .keys
            .lock()
            .inspect_err(|e| {
                error!("Server mutex poisoned: {e}");
            })
            .ok()?
            .get(identity)
            .cloned();

        // Use try_send for non-blocking behavior. Ignore error if receiver dropped.
        let _ = self
            .identity_sender
            .try_send(identity.to_vec())
            .assume("Failed to send identity");

        id_key.map(|(_, key)| key)
    }
}

#[derive(Debug)]
/// Contains thread-safe references to [PresharedKey]s.
/// Used by [`super::Syncer`]
pub struct ClientPresharedKeys {
    key_refs: SyncMutex<HashMap<TeamId, Arc<PresharedKey>>>,
}

impl ClientPresharedKeys {
    pub(super) fn new<I>(initial_keys: I) -> Self
    where
        I: IntoIterator<Item = TeamIdPSKPair>,
    {
        let key_refs = initial_keys.into_iter().collect();
        Self {
            key_refs: SyncMutex::new(key_refs),
        }
    }

    fn insert(&self, id: TeamId, psk: Arc<PresharedKey>) -> Result<()> {
        match self.key_refs.lock() {
            Ok(ref mut map) => {
                map.insert(id, psk);
            }
            Err(e) => bail!(e.to_string()),
        }

        Ok(())
    }

    /// Handle PSK insertion and removal updates.
    pub fn handle_msg(&self, msg: Msg) {
        match msg {
            Msg::Insert((team_id, psk)) => {
                let _ = self
                    .insert(team_id, psk)
                    .inspect_err(|err| error!(err = ?err, "unable to insert PSK"));
            }
            Msg::Remove(_team_id) => {
                todo!("Add remove method to `ClientPresharedKeys`")
            }
        }
    }
}

impl PresharedKeyStore for ClientPresharedKeys {
    #![allow(clippy::expect_used)]
    fn psks(&self, _server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        // TODO: don't panic here
        let key_map = self.key_refs.lock().expect("Client PSK mutex poisoned");
        key_map.values().map(Arc::clone).collect()
    }
}

#[inline(always)]
fn identity_user_str(id: &TeamId) -> String {
    format!("{id}-identity")
}

#[inline(always)]
fn secret_user_str(id: &TeamId) -> String {
    format!("{id}-secret")
}

pub(crate) async fn get_existing_psks<EN, SP: StorageProvider>(
    client: AranyaClient<EN, SP>,
    service_name: &str,
) -> Result<Vec<TeamIdPSKPair>> {
    let mut aranya_client = client.lock().await;
    let graph_id_iter = aranya_client
        .provider()
        .list_graph_ids()?
        .flatten()
        .map(|id| TeamId::from(*id.as_array()));

    let mut keys = Vec::new();
    for id in graph_id_iter {
        let identity = {
            let user_string = identity_user_str(&id);
            let Ok(entry) = keyring::Entry::new(service_name, &user_string) else {
                continue;
            };
            let Ok(identity) = entry.get_secret().inspect_err(|e| error!(%e)) else {
                debug!("Unable to get PSK identity for graph_id: {id}");
                continue;
            };
            identity
        };

        let secret = {
            let user_string = secret_user_str(&id);
            let Ok(entry) = keyring::Entry::new(service_name, &user_string) else {
                continue;
            };
            let Ok(secret) = entry.get_secret().inspect_err(|e| error!(%e)) else {
                debug!("Unable to get PSK secret for graph_id: {id}");
                continue;
            };
            secret
        };

        let Some(psk) = PresharedKey::external(&identity, &secret) else {
            debug!("Unable to create external PSK for graph_id: {id}");
            continue;
        };
        keys.push((id, Arc::new(psk)));
    }

    Ok(keys)
}

/// Inserts a PSK's identity and secret in the platform's credential store
pub(crate) fn insert_psk(
    service_name: &str,
    id: &TeamId,
    identity: &[u8],
    secret: &[u8],
) -> Result<()> {
    {
        let user_string = identity_user_str(id);
        let entry = keyring::Entry::new(service_name, &user_string)?;
        entry.set_secret(identity).inspect_err(|e| error!(%e))?;
    }

    {
        let user_string = secret_user_str(id);
        let entry = keyring::Entry::new(service_name, &user_string)?;
        entry.set_secret(secret).inspect_err(|e| error!(%e))?;
    }

    Ok(())
}

/// Deletes a PSK's identity and secret in the platform's credential store
pub(crate) fn delete_psk(service_name: &str, id: &TeamId) -> Result<()> {
    {
        let user_string = identity_user_str(id);
        let entry = keyring::Entry::new(service_name, &user_string)?;
        entry.delete_credential().inspect_err(|e| error!(%e))?;
    }

    {
        let user_string = secret_user_str(id);
        let entry = keyring::Entry::new(service_name, &user_string)?;
        entry.delete_credential().inspect_err(|e| error!(%e))?;
    }

    Ok(())
}
