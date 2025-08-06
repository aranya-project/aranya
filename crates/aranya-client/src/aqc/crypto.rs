use std::{
    collections::HashMap,
    mem,
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
    keys: Mutex<HashMap<PskIdAsKey, Arc<[Arc<PresharedKey>]>>>,
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
        if keys.insert(PskIdAsKey(psk), [].into()).is_some() {
            error!("Duplicate PSK identity inserted: {:?}", identity);
        }
    }

    /// Load AQC channel PSKs into server key store.
    pub fn load_psks(&self, psks: AqcPsks) {
        let mut keys = self.keys.lock().expect("poisoned");

        let psks: Vec<Arc<PresharedKey>> = psks
            .into_iter()
            .map(|(suite, psk)| make_preshared_key(suite, psk).expect("can make psk"))
            .collect();
        psks.iter().for_each(|psk| {
            keys.insert(PskIdAsKey(psk.clone()), psks.as_slice().into());
        });
    }
}

impl SelectsPresharedKeys for ServerPresharedKeys {
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        Some(
            self.keys
                .lock()
                .expect("poisoned")
                .get_key_value(identity)?
                .0
                 .0
                .clone(),
        )
    }

    fn chosen(&self, identity: &[u8]) {
        // Don't remove ctrl PSK.
        if identity == CTRL_PSK.identity() {
            return;
        }

        let mut keys = self.keys.lock().expect("poisoned");
        if let Some(psks) = keys.remove(identity) {
            for psk in psks.iter() {
                keys.remove(psk.identity());
            }
        }
    }
}

#[derive(Debug)]
pub struct ClientPresharedKeys {
    keys: Mutex<Vec<Arc<PresharedKey>>>,
}

impl ClientPresharedKeys {
    pub fn new(key: Arc<PresharedKey>) -> Self {
        Self {
            keys: Mutex::new(vec![key]),
        }
    }

    pub fn set_key(&self, key: Arc<PresharedKey>) {
        let mut keys_guard = self.keys.lock().expect("Client PSK mutex poisoned");
        keys_guard.clear();
        keys_guard.push(key);
    }

    pub fn load_psks(&self, psks: AqcPsks) {
        let keys = psks
            .into_iter()
            .map(|(suite, psk)| make_preshared_key(suite, psk))
            .collect::<Option<Vec<_>>>()
            .expect("can create psks");
        *self.keys.lock().expect("poisoned") = keys;
    }
}

impl PresharedKeyStore for ClientPresharedKeys {
    fn psks(&self, _server_name: &rustls::pki_types::ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        mem::take(&mut self.keys.lock().expect("poisoned"))
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
