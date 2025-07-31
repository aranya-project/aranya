use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap},
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
use tokio::sync::mpsc;
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
    keys: Mutex<HashMap<Vec<u8>, Arc<PresharedKey>>>,
    // Optional sender to report the selected identity
    identity_sender: mpsc::Sender<Vec<u8>>,
}

impl ServerPresharedKeys {
    pub fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        // Create the mpsc channel for PSK identities
        let (identity_tx, identity_rx) = mpsc::channel::<Vec<u8>>(1);

        (
            Self {
                keys: Mutex::default(),
                identity_sender: identity_tx,
            },
            identity_rx,
        )
    }

    pub fn insert(&self, psk: Arc<PresharedKey>) {
        let identity = psk.identity().to_vec();
        match self.keys.lock().expect("poisoned").entry(identity.clone()) {
            Entry::Vacant(v) => {
                v.insert(psk);
            }
            Entry::Occupied(_) => {
                error!("Duplicate PSK identity inserted: {:?}", identity);
            }
        }
    }

    pub fn zeroize_psks(&self, identities: &[PskIdentity]) {
        let mut keys = self.keys.lock().expect("poisoned");
        identities.iter().for_each(|i| {
            keys.remove(i);
        });
    }

    pub fn load_psks(&self, psks: AqcPsks) {
        let mut keys = self.keys.lock().expect("poisoned");
        for (suite, psk) in psks {
            let identity = psk.identity().as_bytes().to_vec();
            let key = make_preshared_key(suite, psk).expect("can make psk");
            keys.insert(identity, key);
        }
    }

    pub fn clear(&self) {
        self.keys.lock().expect("poisoned").clear()
    }
}

impl SelectsPresharedKeys for ServerPresharedKeys {
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        self.keys.lock().expect("poisoned").get(identity).cloned()
    }

    fn chosen(&self, identity: &[u8]) {
        // Use try_send for non-blocking behavior.
        self.identity_sender
            .try_send(identity.to_vec())
            .expect("Failed to send identity");
    }
}

#[derive(Debug)]
pub struct ClientPresharedKeys {
    keys: Mutex<BTreeMap<PskIdentity, Arc<PresharedKey>>>,
}

impl ClientPresharedKeys {
    pub fn new(key: Arc<PresharedKey>) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(key.identity().to_vec(), key);
        Self {
            keys: Mutex::new(keys),
        }
    }

    pub fn set_key(&self, key: Arc<PresharedKey>) {
        let mut keys_guard = self.keys.lock().expect("Client PSK mutex poisoned");
        keys_guard.clear();
        keys_guard.insert(key.identity().to_vec(), key);
    }

    pub fn load_psks(&self, psks: AqcPsks) {
        let mut keys = self.keys.lock().expect("poisoned");
        keys.clear();
        for (suite, psk) in psks {
            let identity = psk.identity().as_bytes().to_vec();
            let key = make_preshared_key(suite, psk).expect("can make psk");
            keys.insert(identity, key);
        }
    }

    pub fn zeroize_psks(&self, identities: &[PskIdentity]) {
        let mut keys = self.keys.lock().expect("poisoned");
        identities.iter().for_each(|i| {
            keys.remove(i);
        });
    }

    pub fn clear(&self) {
        self.keys.lock().expect("poisoned").clear()
    }
}

impl PresharedKeyStore for ClientPresharedKeys {
    fn psks(&self, _server_name: &rustls::pki_types::ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        self.keys
            .lock()
            .expect("Client PSK mutex poisoned")
            .iter()
            .map(|(_, p)| p.clone())
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
