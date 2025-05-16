//! PSK setup for rustls for use with QUIC connections

use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, Mutex as SyncMutex},
};

use ::rustls::{client::PresharedKeyStore, crypto::PresharedKey, server::SelectsPresharedKeys};
use anyhow::Context;
use aranya_runtime::StorageProvider;
use buggy::BugExt as _;
use s2n_quic::provider::tls::rustls::rustls::pki_types::ServerName;
use tokio::sync::mpsc;
use tracing::{debug, error};

use super::AranyaClient;
use crate::{config::NonEmptyString, daemon::TEAM_ID};

// FIXME
// PSK is hard-coded to prototype the QUIC syncer until PSK key management is complete.
/// PSK secret bytes.
const PSK_BYTES: &[u8; 32] = b"this-is-a-32-byte-secret-psk!!!!"; // 32 bytes

#[derive(Debug)]
pub(super) struct ServerPresharedKeys {
    keys: HashMap<Vec<u8>, Arc<PresharedKey>>,
    // Optional sender to report the selected identity
    identity_sender: mpsc::Sender<Vec<u8>>,
}

impl ServerPresharedKeys {
    pub(super) fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        // Create the mpsc channel for PSK identities
        let (identity_tx, identity_rx) = mpsc::channel::<Vec<u8>>(10);

        (
            Self {
                keys: HashMap::new(),
                identity_sender: identity_tx,
            },
            identity_rx,
        )
    }

    pub(super) fn insert(&mut self, psk: PresharedKey) {
        let identity = psk.identity().to_vec();
        match self.keys.entry(identity.clone()) {
            Entry::Vacant(v) => {
                v.insert(Arc::new(psk));
            }
            Entry::Occupied(_) => {
                error!("Duplicate PSK identity inserted: {:?}", identity);
            }
        }
    }
}

impl SelectsPresharedKeys for ServerPresharedKeys {
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        let key = self.keys.get(identity).cloned();

        // Use try_send for non-blocking behavior. Ignore error if receiver dropped.
        let _ = self
            .identity_sender
            .try_send(identity.to_vec())
            .assume("Failed to send identity");

        key
    }
}

#[derive(Debug)]
pub(crate) struct ClientPresharedKeys {
    key_ref: Arc<SyncMutex<Arc<PresharedKey>>>,
}

impl ClientPresharedKeys {
    pub(super) fn new(key: PresharedKey) -> Self {
        Self {
            key_ref: Arc::new(SyncMutex::new(Arc::new(key))),
        }
    }

    // TODO: if we need to set PSK to something else
    /*
    pub(crate) fn set_key(&self, key: PresharedKey) {
        let mut key_guard = self.key_ref.lock().expect("Client PSK mutex poisoned");
        *key_guard = Arc::new(key);
    }
    */
}

impl PresharedKeyStore for ClientPresharedKeys {
    #![allow(clippy::expect_used)]
    fn psks(&self, _server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        // TODO: don't panic here
        let key_guard = self.key_ref.lock().expect("Client PSK mutex poisoned");
        vec![key_guard.clone()]
    }
}

pub(crate) fn set_sync_psk(service_name: &NonEmptyString) -> anyhow::Result<()> {
    let id_string = TEAM_ID.to_string();
    let entry = keyring::Entry::new(service_name, &id_string)?;

    let _ = entry.set_secret(PSK_BYTES).inspect_err(|e| error!(%e));

    Ok(())
}

pub(crate) fn load_sync_psk(service_name: &NonEmptyString) -> anyhow::Result<PresharedKey> {
    let id_string = TEAM_ID.to_string();
    let entry = keyring::Entry::new(service_name, &id_string)?;
    let secret = entry
        .get_secret()
        .context("Couldn't retreive secret for PSK")?;

    Ok(PresharedKey::external(id_string.as_bytes(), &secret).assume("unable to create PSK")?)
}

pub(super) async fn get_existing_psks<EN, SP: StorageProvider>(
    client: AranyaClient<EN, SP>,
    service_name: &NonEmptyString,
) -> anyhow::Result<Vec<PresharedKey>> {
    let mut aranya_client = client.lock().await;
    let graph_id_iter = aranya_client.provider().list_graph_ids()?.flatten();

    let mut keys = Vec::new();
    for id in graph_id_iter {
        let id_string = id.to_string();
        let Ok(entry) = keyring::Entry::new(service_name, &id_string) else {
            continue;
        };
        let Ok(secret) = entry.get_secret() else {
            debug!("Unable to get PSK secret for graph_id {id_string}");
            continue;
        };

        let Some(psk) = PresharedKey::external(id_string.as_bytes(), &secret) else {
            continue;
        };
        keys.push(psk);
    }

    Ok(keys)
}
