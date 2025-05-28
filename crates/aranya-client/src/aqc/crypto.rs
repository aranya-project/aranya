use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, LazyLock, Mutex},
};

use aranya_daemon_api::{AqcPsk, AqcPsks, CipherSuiteId};
use rustls::{
    client::PresharedKeyStore,
    crypto::{hash::HashAlgorithm, CryptoProvider, PresharedKey},
    server::SelectsPresharedKeys,
};
use s2n_quic::provider::tls::rustls::rustls::pki_types::ServerName;
use tokio::sync::mpsc;
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

    pub fn load_psks(&self, psks: AqcPsks) {
        let mut keys = self.keys.lock().expect("poisoned");
        for (suite, psk) in psks {
            let identity = psk.identity().as_bytes().to_vec();
            let key = make_preshared_key(suite, psk).expect("can make psk");
            keys.insert(identity, key);
        }
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
    fn psks(&self, _server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        self.keys.lock().expect("Client PSK mutex poisoned").clone()
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

// --- Start SkipServerVerification ---
// INSECURE: Allows connecting to any server certificate.
// Requires the `dangerous_configuration` feature on the `rustls` crate.
// Use full paths for traits and types
// TODO: remove this once we have a way to exclusively use PSKs.
// Currently, we use this to allow the server to be set up to use PSKs
// without having to rely on the server certificate.

#[derive(Debug)]
pub struct SkipServerVerification(&'static CryptoProvider);

impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
        let provider = CryptoProvider::get_default().expect("Default crypto provider not found");
        Arc::new(Self(provider))
    }
}

// Use full trait path
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Use the selected provider's verification algorithms
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Use the selected provider's verification algorithms
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
// --- End SkipServerVerification ---

#[derive(Debug, Default)]
pub struct NoCertResolver(Arc<NoSigningKey>);
impl rustls::server::ResolvesServerCert for NoCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::new(rustls::sign::CertifiedKey::new(
            vec![],
            Arc::clone(&self.0) as _,
        )))
    }
}

#[derive(Debug, Default)]
pub struct NoSigningKey;
impl rustls::sign::SigningKey for NoSigningKey {
    fn choose_scheme(
        &self,
        _offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        None
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}
