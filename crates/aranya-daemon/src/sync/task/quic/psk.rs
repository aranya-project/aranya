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
    inner: SyncMutex<PskStoreInner>,
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
                inner: SyncMutex::new(PskStoreInner {
                    active_team: None,
                    team_identities,
                    identity_psk,
                }),
                active_team_tx,
            },
            active_team_rx,
        )
    }

    pub(crate) fn insert(&self, team_id: TeamId, psk: Arc<PresharedKey>) -> Result<()> {
        match self.inner.lock() {
            Ok(ref mut inner) => {
                let identity = Bytes::copy_from_slice(psk.identity());

                {
                    let identities = inner.team_identities.entry(team_id).or_default();
                    identities.push(identity.clone());
                }

                inner.identity_psk.insert(identity, psk);
                Ok(())
            }
            Err(e) => bail!(e.to_string()),
        }
    }

    pub(crate) fn remove(&self, _id: TeamId) -> Result<()> {
        todo!("Implement this method. https://github.com/aranya-project/aranya/pull/302")
    }

    #[allow(clippy::expect_used)]
    pub(crate) fn set_team(&self, team_id: TeamId) {
        let mut inner = self.inner.lock().expect("poisoned mutex");
        let _ = inner.active_team.replace(team_id);
    }
}

impl PresharedKeyStore for PskStore {
    #[allow(clippy::expect_used)]
    fn psks(&self, _server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        let inner = self.inner.lock().expect("poisoned mutex");

        let Some(active_team) = inner.active_team.as_ref() else {
            return Vec::new();
        };
        let Some(active_identities) = inner.team_identities.get(active_team) else {
            return Vec::new();
        };

        let mut psks = Vec::new();
        for identity in active_identities {
            if let Some(psk) = inner.identity_psk.get(identity) {
                psks.push(Arc::clone(psk));
            }
        }
        psks
    }
}

impl SelectsPresharedKeys for PskStore {
    #[allow(clippy::expect_used)]
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        let inner = self
            .inner
            .lock()
            .inspect_err(|e| error!("mutex poisoned: {e}"))
            .ok()?;

        inner.identity_psk.get(identity).cloned()
    }

    #[allow(clippy::expect_used)]
    fn chosen(&self, identity: &[u8]) {
        let inner = self.inner.lock().expect("poisoned mutex");

        // TODO(Steve): More efficient approach
        for (team_id, identities) in inner.team_identities.iter() {
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

#[derive(Debug)]
struct PskStoreInner {
    team_identities: HashMap<TeamId, Vec<Bytes>>,
    identity_psk: HashMap<Bytes, Arc<PresharedKey>>,
    active_team: Option<TeamId>,
}
