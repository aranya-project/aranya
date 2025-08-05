use std::{
    collections::HashSet,
    sync::{Arc, LazyLock, Mutex},
};

use aranya_daemon_api::{AqcPsk, AqcPsks, CipherSuiteId};
#[allow(deprecated)]
use s2n_quic::provider::tls::rustls::rustls::{
    self,
    client::PresharedKeyStore,
    crypto::{hash::HashAlgorithm, PresharedKey},
    server::SelectsPresharedKeys,
};
use tracing::error;

use crate::aqc::net::PskIdentity;

// Define constant PSK identity and bytes
pub(super) const PSK_IDENTITY_CTRL: &[u8; 16] = b"aranya-ctrl-psk!"; // 16 bytes
const PSK_BYTES_CTRL: &[u8; 32] = b"this-is-a-32-byte-secret-psk!!!!"; // 32 bytes

pub(super) static CTRL_PSK: LazyLock<Arc<PresharedKey>> = LazyLock::new(|| {
    let psk = PresharedKey::external(PSK_IDENTITY_CTRL, PSK_BYTES_CTRL)
        .expect("identity and bytes are small and nonzero");
    let psk = psk
        .with_hash_alg(HashAlgorithm::SHA384)
        .expect("valid hash alg");
    Arc::new(psk)
});

#[derive(Debug)]
pub(crate) struct ServerPresharedKeys {
    keys: Mutex<HashSet<PskIdAsKey>>,
}

impl ServerPresharedKeys {
    pub fn new() -> Self {
        Self {
            keys: Mutex::default(),
        }
    }

    /// Insert PSK into server key store.
    pub fn insert(&self, psk: Arc<PresharedKey>) {
        let identity = psk.identity().to_vec();
        let mut keys = self.keys.lock().expect("poisoned");
        if !keys.insert(PskIdAsKey(psk)) {
            error!("Duplicate PSK identity inserted: {:?}", identity);
        }
    }

    /// Zeroize PSKs with the provided identities.
    /// Removes the PSKs from the map so the secret can be zeroized via `Zeroizing` when dropped.
    /// Assumes there are no other references to the zeroized PSKs held long-term outside of this keystore.
    pub fn remove(&self, identities: &[PskIdentity]) {
        let mut keys = self.keys.lock().expect("poisoned");
        identities.iter().for_each(|i| {
            keys.remove(i.as_slice());
        });
    }

    /// Load PSKs into server key store.
    pub fn load_psks(&self, psks: AqcPsks) {
        let mut keys = self.keys.lock().expect("poisoned");
        for (suite, psk) in psks {
            let key = make_preshared_key(suite, psk).expect("can make psk");
            keys.insert(PskIdAsKey(key));
        }
    }
}

impl SelectsPresharedKeys for ServerPresharedKeys {
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        Some(self.keys.lock().expect("poisoned").get(identity)?.0.clone())
    }
}

#[derive(Debug)]
pub struct ClientPresharedKeys {
    keys: Mutex<HashSet<PskIdAsKey>>,
}

impl ClientPresharedKeys {
    pub fn new(key: Arc<PresharedKey>) -> Self {
        let mut keys = HashSet::new();
        keys.insert(PskIdAsKey(key));
        Self {
            keys: Mutex::new(keys),
        }
    }

    pub fn set_key(&self, key: Arc<PresharedKey>) {
        let mut keys_guard = self.keys.lock().expect("Client PSK mutex poisoned");
        keys_guard.clear();
        keys_guard.insert(PskIdAsKey(key));
    }

    pub fn load_psks(&self, psks: AqcPsks) {
        let mut keys = self.keys.lock().expect("poisoned");
        for (suite, psk) in psks {
            let key = make_preshared_key(suite, psk).expect("can make psk");
            keys.insert(PskIdAsKey(key));
        }
    }
}

impl PresharedKeyStore for ClientPresharedKeys {
    fn psks(&self, _server_name: &rustls::pki_types::ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        self.keys
            .lock()
            .expect("Client PSK mutex poisoned")
            .drain()
            .map(|p| p.0)
            .collect()
    }
}

fn make_preshared_key(suite: CipherSuiteId, psk: AqcPsk) -> Option<Arc<PresharedKey>> {
    let key = PresharedKey::external(psk.identity().as_bytes(), psk.secret())?
        .with_hash_alg(suite_hash(suite)?)?;
    Some(Arc::new(key))
}

fn suite_hash(suite: CipherSuiteId) -> Option<HashAlgorithm> {
    Some(match suite {
        CipherSuiteId::TlsAes128GcmSha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes256GcmSha384 => HashAlgorithm::SHA384,
        CipherSuiteId::TlsChaCha20Poly1305Sha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes128CcmSha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes128Ccm8Sha256 => HashAlgorithm::SHA256,
        _ => return None,
    })
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
