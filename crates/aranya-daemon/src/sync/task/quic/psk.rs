//! PSK setup for rustls for use with QUIC connections

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as SyncMutex},
};

use anyhow::{bail, Result};
use aranya_daemon_api::TeamId;
use buggy::BugExt as _;
use bytes::Bytes;
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
    team_identities: SyncMutex<HashMap<TeamId, Vec<Bytes>>>,
    identity_psk: SyncMutex<HashMap<Bytes, Arc<PresharedKey>>>,
    active_team: SyncMutex<Option<TeamId>>,
    // Optional sender to report the selected team
    active_team_tx: mpsc::Sender<TeamId>,
}

impl PskStore {
    pub(crate) fn new<I>(initial_keys: I) -> (Self, mpsc::Receiver<TeamId>)
    where
        I: IntoIterator<Item = TeamIdPSKPair>,
    {
        let mut team_identities = HashMap::new();
        let mut identity_psk = HashMap::new();

        for (team_id, psk) in initial_keys {
            let identity = Bytes::copy_from_slice(psk.identity());
            let identities: &mut Vec<Bytes> = team_identities.entry(team_id).or_default();
            identities.push(identity.clone());

            identity_psk.insert(identity, psk);
        }

        let (active_team_tx, active_team_rx) = mpsc::channel::<TeamId>(10);
        (
            Self {
                active_team: SyncMutex::new(None),
                team_identities: SyncMutex::new(team_identities),
                identity_psk: SyncMutex::new(identity_psk),
                active_team_tx,
            },
            active_team_rx,
        )
    }

    pub(crate) fn insert(&self, team_id: TeamId, psk: Arc<PresharedKey>) -> Result<()> {
        match (self.team_identities.lock(), self.identity_psk.lock()) {
            // Use a single mutex for both maps?
            (Ok(ref mut id_team), Ok(ref mut id_psk)) => {
                let identity = Bytes::copy_from_slice(psk.identity());
                let identities = id_team.entry(team_id).or_default();
                identities.push(identity.clone());
                id_psk.insert(identity, psk);
            }
            (Err(e1), Err(e2)) => bail!("err1: {e1}, err2: {e2}"),
            (Err(e), _) => bail!(e.to_string()),
            (_, Err(e)) => bail!(e.to_string()),
        }

        Ok(())
    }

    pub(crate) fn remove(&self, _id: TeamId) -> Result<()> {
        todo!("Implement this method. https://github.com/aranya-project/aranya/pull/302")
    }

    #[allow(clippy::expect_used)]
    pub(crate) fn set_team(&self, team_id: TeamId) {
        let _ = self
            .active_team
            .lock()
            .expect("poisoned active team mutex")
            .replace(team_id);
    }
}

impl PresharedKeyStore for PskStore {
    #[allow(clippy::expect_used)]
    fn psks(&self, _server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        let guard = self.active_team.lock().expect("poisoned active_team mutex");
        let Some(active_team) = guard.as_ref() else {
            return Vec::new();
        };

        // TODO: don't panic here.
        let team_ids = self
            .team_identities
            .lock()
            .expect("Client PSK mutex poisoned");

        let Some(active_identities) = team_ids.get(active_team) else {
            return Vec::new();
        };
        let id_psks = self.identity_psk.lock().expect("Client PSK mutex poisoned");
        let mut psks = Vec::new();

        for identity in active_identities {
            if let Some(psk) = id_psks.get(identity) {
                psks.push(Arc::clone(psk));
            }
        }
        psks
    }
}

impl SelectsPresharedKeys for PskStore {
    #[allow(clippy::expect_used)]
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        self.identity_psk
            .lock()
            .inspect_err(|e| {
                error!("Server mutex poisoned: {e}");
            })
            .ok()?
            .get(identity)
            .cloned()
    }

    #[allow(clippy::expect_used)]
    fn chosen(&self, identity: &[u8]) {
        let team_identities = self.team_identities.lock().expect("mutex poisoned");

        // TODO(Steve): More efficient approach
        for (team_id, identities) in team_identities.iter() {
            if identities.iter().any(|id| id == identity) {
                // Use try_send for non-blocking behavior. Ignore error if receiver dropped.
                let _ = self
                    .active_team_tx
                    .try_send(*team_id)
                    .assume("Failed to send identity");

                break;
            }
        }
    }
}
