//! This module provides TLS configuration components that **deliberately bypass security checks**.

// --- Start SkipServerVerification ---
// INSECURE: Allows connecting to any server certificate.
// Requires the `dangerous_configuration` feature on the `rustls` crate.
// Use full paths for traits and types
// TODO: remove this once we have a way to exclusively use PSKs.
// Currently, we use this to allow the server to be set up to use PSKs
// without having to rely on the server certificate.

use std::sync::Arc;

use s2n_quic::provider::tls::rustls::rustls::pki_types::ServerName;
#[allow(deprecated)]
use s2n_quic::provider::tls::rustls::rustls::{self, crypto::CryptoProvider};

#[derive(Debug)]
/// A server certificate verifier that accepts any certificate without validation.
///
/// This struct implements [`rustls::client::danger::ServerCertVerifier`] but performs no actual
/// certificate verification, effectively accepting any server certificate presented during
/// the TLS handshake.
pub struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    #![allow(clippy::expect_used)]
    /// Creates a new instance using the default [`CryptoProvider`]
    pub fn new() -> Arc<Self> {
        let provider = CryptoProvider::get_default().expect("Default crypto provider not found");
        Arc::new(Self(provider.clone()))
    }
}

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

/// A certificate resolver that provides no certificates.
///
/// This struct implements [`rustls::server::ResolvesServerCert`] but returns an empty
/// certificate chain with a non-functional signing key. This is intended for server
/// configurations that rely exclusively on Pre-Shared Keys (PSKs) for authentication.
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

/// A non-functional signing key implementation that performs no actual signing.
///
/// This struct implements [`rustls::sign::SigningKey`].
/// It's used internally by [`NoCertResolver`].
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
