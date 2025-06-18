//! PSK setup for rustls for use with QUIC connections

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as SyncMutex},
};

use anyhow::{bail, Result};
use aranya_daemon_api::TeamId;
use buggy::BugExt as _;
use s2n_quic::provider::tls::rustls::rustls::{
    client, crypto::PresharedKey, pki_types::ServerName, server,
};
use tokio::sync::mpsc;
use tracing::{error, warn};

pub(crate) type TeamIdPSKPair = (TeamId, Arc<PresharedKey>);

pub(crate) const QUIC_SYNC_PSK_CONTEXT: &[u8] = b"AranyaQuicSync-v1";

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
        let mut team_identities = HashMap::<TeamId, Vec<Arc<PresharedKey>>>::new();
        let mut identity_psk = HashMap::new();

        for (team_id, psk) in initial_keys {
            team_identities
                .entry(team_id)
                .or_default()
                .push(Arc::clone(&psk));
            identity_psk.insert(PskIdAsKey(psk), team_id);
        }

        let (active_team_tx, active_team_rx) = mpsc::channel::<TeamId>(10);
        (
            Self {
                inner: SyncMutex::new(PskStoreInner {
                    active_team: None,
                    team_identities,
                    identity_team: identity_psk,
                }),
                active_team_tx,
            },
            active_team_rx,
        )
    }

    pub(crate) fn insert(&self, team_id: TeamId, psk: Arc<PresharedKey>) -> Result<()> {
        match self.inner.lock() {
            Ok(ref mut inner) => {
                inner
                    .team_identities
                    .entry(team_id)
                    .or_default()
                    .push(Arc::clone(&psk));
                inner.identity_team.insert(PskIdAsKey(psk), team_id);
                Ok(())
            }
            Err(e) => bail!(e.to_string()),
        }
    }

    pub(crate) fn remove(&self, team_id: TeamId) -> Result<()> {
        match self.inner.lock() {
            Ok(ref mut inner) => {
                inner.team_identities.remove(&team_id);

                inner.identity_team.retain(|_, other| *other != team_id);

                Ok(())
            }
            Err(e) => bail!(e.to_string()),
        }
    }

    #[allow(clippy::expect_used)]
    pub(crate) fn set_team(&self, team_id: TeamId) {
        let mut inner = self.inner.lock().expect("poisoned mutex");
        let _ = inner.active_team.replace(team_id);
    }
}

impl client::PresharedKeyStore for PskStore {
    #[allow(clippy::expect_used)]
    fn psks(&self, _server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        let inner = self.inner.lock().expect("poisoned mutex");

        let Some(active_team) = inner.active_team.as_ref() else {
            return Vec::new();
        };
        let Some(active_identities) = inner.team_identities.get(active_team) else {
            return Vec::new();
        };
        active_identities.clone()
    }
}

impl server::SelectsPresharedKeys for PskStore {
    #[allow(clippy::expect_used)]
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        let inner = self
            .inner
            .lock()
            .inspect_err(|e| error!("mutex poisoned: {e}"))
            .ok()?;

        let (k, _) = inner.identity_team.get_key_value(identity)?;
        Some(k.0.clone())
    }

    #[allow(clippy::expect_used)]
    fn chosen(&self, identity: &[u8]) {
        let inner = self.inner.lock().expect("poisoned mutex");
        let Some(team_id) = inner.identity_team.get(identity) else {
            warn!("identity removed?");
            return;
        };
        self.active_team_tx
            .try_send(*team_id)
            .assume("Failed to send identity")
            .ok();
    }
}

#[derive(Debug)]
struct PskStoreInner {
    team_identities: HashMap<TeamId, Vec<Arc<PresharedKey>>>,
    identity_team: HashMap<PskIdAsKey, TeamId>,
    active_team: Option<TeamId>,
}

#[derive(Debug)]
struct PskIdAsKey(Arc<PresharedKey>);
impl core::hash::Hash for PskIdAsKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.identity().hash(state);
    }
}
impl core::borrow::Borrow<[u8]> for PskIdAsKey {
    fn borrow(&self) -> &[u8] {
        self.0.identity()
    }
}
impl Eq for PskIdAsKey {}
impl PartialEq for PskIdAsKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.identity() == other.0.identity()
    }
}
