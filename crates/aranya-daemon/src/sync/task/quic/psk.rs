//! PSK setup for rustls for use with QUIC connections

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as SyncMutex},
};

use anyhow::{bail, Result};
use aranya_daemon_api::TeamId;
use buggy::BugExt as _;
use s2n_quic::provider::tls::rustls::rustls::{
    client::PresharedKeyStore, crypto::PresharedKey, pki_types::ServerName,
    server::SelectsPresharedKeys,
};
use tokio::sync::mpsc;
use tracing::error;

pub(crate) type TeamIdPSKPair = (TeamId, Arc<PresharedKey>);

/// PSK store that's shared between [`super::Syncer`]
/// and [`super::Server`]
#[derive(Debug)]
pub struct PskStore {
    keys: SyncMutex<HashMap<Vec<u8>, TeamIdPSKPair>>,
    // Optional sender to report the selected identity
    identity_tx: mpsc::Sender<Vec<u8>>,
}

impl PskStore {
    pub(crate) fn new<I>(initial_keys: I) -> (Self, mpsc::Receiver<Vec<u8>>)
    where
        I: IntoIterator<Item = TeamIdPSKPair>,
    {
        let keys = initial_keys
            .into_iter()
            .map(|(team_id, psk)| (psk.identity().into(), (team_id, psk)))
            .collect();
        let (identity_tx, identity_rx) = mpsc::channel::<Vec<u8>>(10);
        (
            Self {
                keys: SyncMutex::new(keys),
                identity_tx,
            },
            identity_rx,
        )
    }

    pub(crate) fn insert(&self, id: TeamId, psk: Arc<PresharedKey>) -> Result<()> {
        match self.keys.lock() {
            Ok(ref mut map) => {
                map.insert(psk.identity().to_vec(), (id, psk));
            }
            Err(e) => bail!(e.to_string()),
        }

        Ok(())
    }

    pub(crate) fn remove(&self, _id: TeamId) -> Result<()> {
        todo!("Implement this method. https://github.com/aranya-project/aranya/pull/302")
    }
}

impl PresharedKeyStore for PskStore {
    #![allow(clippy::expect_used)]
    fn psks(&self, _server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        // TODO: don't panic here
        let key_map = self.keys.lock().expect("Client PSK mutex poisoned");
        key_map
            .values()
            .map(|(_, key)| key)
            .map(Arc::clone)
            .collect()
    }
}

impl SelectsPresharedKeys for PskStore {
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
            .identity_tx
            .try_send(identity.to_vec())
            .assume("Failed to send identity");

        id_key.map(|(_, key)| key)
    }
}
