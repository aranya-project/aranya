//! PSK setup for rustls for use with QUIC connections

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as SyncMutex},
};

use anyhow::{bail, Context as _, Result};
use aranya_crypto::{
    id::IdError, policy::GroupId, tls::PskSeedId, Csprng, Identified as _, KeyStoreExt as _,
    PolicyId,
};
use aranya_daemon_api::{CipherSuiteId, Ikm, TeamId};
use s2n_quic::provider::tls::rustls::rustls::{
    client,
    crypto::{hash::HashAlgorithm, PresharedKey},
    pki_types::ServerName,
    server,
};

use crate::{
    daemon::{CE, CS, KS},
    keystore::LocalStore,
};

pub(crate) type TeamIdPSKPair = (TeamId, Arc<PresharedKey>);

const QUIC_SYNC_PSK_CONTEXT: &[u8] = b"AranyaQuicSync-v1";

#[derive(Clone)]
pub(crate) struct PskSeed(pub(crate) aranya_crypto::tls::PskSeed<CS>);

impl PskSeed {
    pub(crate) fn new(rng: &mut impl Csprng, team: TeamId) -> Self {
        let group = GroupId::from(team.into_id());
        Self(aranya_crypto::tls::PskSeed::new(rng, &group))
    }

    pub(crate) fn import_from_ikm(ikm: &Ikm, team: TeamId) -> Self {
        let group = GroupId::from(team.into_id());
        Self(aranya_crypto::tls::PskSeed::import_from_ikm(
            ikm.raw_ikm_bytes(),
            &group,
        ))
    }

    pub(crate) fn load(
        eng: &mut CE,
        store: &LocalStore<KS>,
        id: PskSeedId,
    ) -> Result<Option<Self>> {
        store
            .get_key(eng, id)
            .map(|r| r.map(Self))
            .map_err(Into::into)
    }

    pub(crate) fn id(&self) -> Result<PskSeedId, IdError> {
        self.0.id()
    }

    pub(crate) fn into_inner(self) -> aranya_crypto::tls::PskSeed<CS> {
        self.0
    }

    pub(crate) fn generate_psks(self, team: TeamId) -> impl Iterator<Item = Result<PresharedKey>> {
        let group = GroupId::from(team.into_id());
        let policy = PolicyId::default();
        self.0
            .generate_psks(
                QUIC_SYNC_PSK_CONTEXT,
                group,
                policy,
                CipherSuiteId::all().iter().copied(),
            )
            .map(|r| {
                let psk = r?;
                psk_to_rustls(psk)
            })
    }
}

fn psk_to_rustls(psk: aranya_crypto::tls::Psk<CS>) -> Result<PresharedKey> {
    let identity = psk.identity().as_bytes();
    let secret = psk.raw_secret_bytes();
    let alg = match psk.identity().cipher_suite() {
        CipherSuiteId::TlsAes128GcmSha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes256GcmSha384 => HashAlgorithm::SHA384,
        CipherSuiteId::TlsChaCha20Poly1305Sha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes128CcmSha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes128Ccm8Sha256 => HashAlgorithm::SHA256,
        cs => bail!("unknown ciphersuite {cs}"),
    };
    let psk = PresharedKey::external(identity, secret)
        .context("unable to create PSK")?
        .with_hash_alg(alg)
        .context("Invalid hash algorithm")?;
    Ok(psk)
}

/// PSK store that's shared between [`super::Syncer`]
/// and [`super::Server`]
#[derive(Debug)]
pub struct PskStore {
    inner: SyncMutex<PskStoreInner>,
}

impl PskStore {
    pub(crate) fn new<I>(initial_keys: I) -> Self
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

        Self {
            inner: SyncMutex::new(PskStoreInner {
                active_team: None,
                team_identities,
                identity_team: identity_psk,
            }),
        }
    }

    pub(crate) fn insert(&self, team_id: TeamId, psk: Arc<PresharedKey>) {
        #[allow(clippy::expect_used, reason = "poison")]
        let mut inner = self.inner.lock().expect("poisoned");
        inner
            .team_identities
            .entry(team_id)
            .or_default()
            .push(Arc::clone(&psk));
        inner.identity_team.insert(PskIdAsKey(psk), team_id);
    }

    pub(crate) fn remove(&self, team_id: TeamId) {
        #[allow(clippy::expect_used, reason = "poison")]
        let mut inner = self.inner.lock().expect("poisoned");
        inner.team_identities.remove(&team_id);
        inner.identity_team.retain(|_, other| *other != team_id);
    }

    pub(crate) fn set_team(&self, team_id: TeamId) {
        #[allow(clippy::expect_used, reason = "poison")]
        let mut inner = self.inner.lock().expect("poisoned");
        let _ = inner.active_team.replace(team_id);
    }

    pub(crate) fn get_team_for_identity(&self, identity: &[u8]) -> Option<TeamId> {
        #[allow(clippy::expect_used, reason = "poison")]
        let inner = self.inner.lock().expect("poisoned");
        inner.identity_team.get(identity).copied()
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
        let inner = self.inner.lock().expect("poison");

        let (k, _) = inner.identity_team.get_key_value(identity)?;
        Some(k.0.clone())
    }
}

#[derive(Debug)]
struct PskStoreInner {
    team_identities: HashMap<TeamId, Vec<Arc<PresharedKey>>>,
    identity_team: HashMap<PskIdAsKey, TeamId>,
    /// Indicates the "active team".
    /// Used by [`PskStore`] to restrict the PSKs that are offered by the client.
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
