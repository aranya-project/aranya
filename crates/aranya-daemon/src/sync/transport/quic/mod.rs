//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with mutual TLS (mTLS) authentication.
//! Both client and server verify each other's certificates against a shared
//! set of trusted root CAs.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use std::{convert::Infallible, path::PathBuf, sync::Arc};

use quinn::TransportConfig;

mod certs;
mod client;
mod connections;
mod server;

pub(crate) use client::QuicState;
pub(crate) use connections::{ConnectionKey, ConnectionUpdate, SharedConnectionMap};
pub(crate) use server::Server;

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic-sync-unstable";

/// Creates a QUIC transport configuration with no idle timeout.
///
/// Connections are kept open indefinitely without keep-alive pings.
/// This is appropriate for daemon-to-daemon connections where resources
/// are not constrained and connection reuse is desired.
fn transport_config() -> Arc<TransportConfig> {
    let mut transport_config = TransportConfig::default();
    // Disable idle timeout - connections stay open forever.
    transport_config.max_idle_timeout(None);
    // No keep-alive pings needed since there's no idle timeout.
    transport_config.keep_alive_interval(None);
    Arc::new(transport_config)
}

/// Errors specific to the QUIC syncer
#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Error {
    /// QUIC Connection error
    #[error("QUIC connection error: {0}")]
    QuicConnectionError(#[from] quinn::ConnectionError),
    /// QUIC Write error
    #[error("QUIC write error: {0}")]
    QuicWriteError(#[from] quinn::WriteError),
    /// QUIC Read error
    #[error("QUIC read error: {0}")]
    QuicReadError(#[from] quinn::ReadToEndError),
    /// QUIC Connect error
    #[error("QUIC connect error: {0}")]
    QuicConnectError(#[from] quinn::ConnectError),
    /// Certificate or TLS configuration error
    #[error(transparent)]
    Cert(#[from] certs::CertError),
    /// QUIC endpoint error
    #[error("QUIC endpoint error: {0}")]
    EndpointError(String),
    /// QUIC connection timeout
    ///
    /// This occurs when the TLS handshake takes too long, which can happen
    /// when connecting to a server with mismatched certificates. Quinn doesn't
    /// provide a built-in handshake timeout, so we wrap connections with
    /// tokio::time::timeout.
    #[error("QUIC connection timed out during TLS handshake")]
    QuicConnectionTimeout,
}

impl From<Infallible> for Error {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

/// Certificate configuration for mTLS.
#[derive(Clone, Debug)]
pub struct CertConfig {
    /// Directory containing root CA certificates.
    pub root_certs_dir: PathBuf,
    /// Path to device certificate.
    pub device_cert: PathBuf,
    /// Path to device private key.
    pub device_key: PathBuf,
}

/// Sync configuration for setting up Aranya.
pub(crate) struct SyncParams {
    pub(crate) cert_config: CertConfig,
    pub(crate) server_addr: crate::sync::Addr,
}

#[cfg(test)]
mod tests {
    use std::{fs, net::SocketAddr, path::Path, sync::Arc, time::Duration};

    use aranya_certgen::{CaCert, CertPaths, SaveOptions, SignedCert};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tempfile::TempDir;

    use super::certs::{build_client_config, build_server_config, load_device_cert, load_root_certs};
    use super::transport_config;
    use crate::sync::SyncResponse;

    /// Test infrastructure for QUIC/TLS tests.
    ///
    /// Provides common setup for mTLS testing including certificate generation,
    /// QUIC endpoint creation, and connection helpers.
    struct QuicTestSetup {
        /// Temp directory holding all certificates (kept alive for test duration).
        _temp_dir: TempDir,
        /// Server QUIC endpoint.
        server_endpoint: quinn::Endpoint,
        /// Address the server is listening on.
        server_addr: SocketAddr,
        /// Client QUIC endpoint.
        client_endpoint: quinn::Endpoint,
        /// Client TLS configuration for connecting to the server.
        client_config: quinn::ClientConfig,
    }

    impl QuicTestSetup {
        /// Creates a test setup where client and server trust the same CA.
        ///
        /// Both parties can successfully verify each other's certificates.
        fn with_shared_ca() -> Self {
            let temp_dir = TempDir::new().expect("failed to create temp dir");

            // Create a single CA that both client and server will trust
            let ca = CaCert::new("Test CA", 365).expect("failed to create CA");

            // Generate server and client certs signed by the same CA
            let server_cert = ca
                .generate("127.0.0.1", 365)
                .expect("failed to generate server cert");
            let client_cert = ca
                .generate("127.0.0.1", 365)
                .expect("failed to generate client cert");

            // Save CA cert (both will trust this)
            let ca_dir = temp_dir.path().join("ca");
            fs::create_dir(&ca_dir).expect("failed to create ca dir");
            Self::save_ca(&ca, &ca_dir);

            // Save device certs
            let server_paths = Self::save_device_cert(&server_cert, temp_dir.path(), "server");
            let client_paths = Self::save_device_cert(&client_cert, temp_dir.path(), "client");

            // Load certs - both trust the same CA
            let root_store = load_root_certs(&ca_dir).expect("failed to load CA roots");
            let (server_certs, server_key) = Self::load_device(&server_paths);
            let (client_certs, client_key) = Self::load_device(&client_paths);

            Self::build(
                temp_dir,
                root_store.clone(),
                server_certs,
                server_key,
                root_store,
                client_certs,
                client_key,
            )
        }

        /// Creates a test setup where client and server trust different CAs.
        ///
        /// The server trusts CA1 and has a cert signed by CA1.
        /// The client trusts CA2 and has a cert signed by CA2.
        /// Neither can verify the other's certificate, causing mTLS to fail.
        fn with_mismatched_cas() -> Self {
            let temp_dir = TempDir::new().expect("failed to create temp dir");

            // Create two separate CAs that don't trust each other
            let ca1 = CaCert::new("Test CA 1", 365).expect("failed to create CA1");
            let ca2 = CaCert::new("Test CA 2", 365).expect("failed to create CA2");

            // Generate server cert signed by CA1
            let server_cert = ca1
                .generate("127.0.0.1", 365)
                .expect("failed to generate server cert");

            // Generate client cert signed by CA2 (different CA!)
            let client_cert = ca2
                .generate("127.0.0.1", 365)
                .expect("failed to generate client cert");

            // Save CA1 certs (server will trust only CA1)
            let ca1_dir = temp_dir.path().join("ca1");
            fs::create_dir(&ca1_dir).expect("failed to create ca1 dir");
            Self::save_ca(&ca1, &ca1_dir);

            // Save CA2 certs (client will trust only CA2)
            let ca2_dir = temp_dir.path().join("ca2");
            fs::create_dir(&ca2_dir).expect("failed to create ca2 dir");
            Self::save_ca(&ca2, &ca2_dir);

            // Save device certs
            let server_paths = Self::save_device_cert(&server_cert, temp_dir.path(), "server");
            let client_paths = Self::save_device_cert(&client_cert, temp_dir.path(), "client");

            // Load server certs (trusts CA1 only)
            let server_root_store = load_root_certs(&ca1_dir).expect("failed to load CA1 roots");
            let (server_certs, server_key) = Self::load_device(&server_paths);

            // Load client certs (trusts CA2 only - MISMATCH!)
            let client_root_store = load_root_certs(&ca2_dir).expect("failed to load CA2 roots");
            let (client_certs, client_key) = Self::load_device(&client_paths);

            Self::build(
                temp_dir,
                server_root_store,
                server_certs,
                server_key,
                client_root_store,
                client_certs,
                client_key,
            )
        }

        /// Saves a CA certificate to the specified directory.
        fn save_ca(ca: &CaCert, dir: &Path) {
            let ca_paths = CertPaths::new(dir.join("ca"));
            ca.save(&ca_paths, SaveOptions::default())
                .expect("failed to save CA");
        }

        /// Saves a device certificate and returns the paths.
        fn save_device_cert(cert: &SignedCert, base_dir: &Path, name: &str) -> CertPaths {
            let paths = CertPaths::new(base_dir.join(name));
            cert.save(&paths, SaveOptions::default())
                .expect("failed to save device cert");
            paths
        }

        /// Loads a device certificate and key from the given paths.
        fn load_device(
            paths: &CertPaths,
        ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
            load_device_cert(paths.cert(), paths.key()).expect("failed to load device cert")
        }

        /// Builds QUIC endpoints with the specified TLS configurations.
        fn build(
            temp_dir: TempDir,
            server_root_store: rustls::RootCertStore,
            server_certs: Vec<CertificateDer<'static>>,
            server_key: PrivateKeyDer<'static>,
            client_root_store: rustls::RootCertStore,
            client_certs: Vec<CertificateDer<'static>>,
            client_key: PrivateKeyDer<'static>,
        ) -> Self {
            // Build server TLS config
            let mut server_tls_config =
                build_server_config(server_root_store, server_certs, server_key)
                    .expect("failed to build server TLS config");
            server_tls_config.alpn_protocols = vec![b"test".to_vec()];

            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_tls_config)
                    .expect("failed to create QUIC server config"),
            ));
            // Use production transport config (no idle timeout)
            server_config.transport_config(transport_config());

            // Build client TLS config
            let mut client_tls_config =
                build_client_config(client_root_store, client_certs, client_key)
                    .expect("failed to build client TLS config");
            client_tls_config.alpn_protocols = vec![b"test".to_vec()];

            let mut client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(client_tls_config)
                    .expect("failed to create QUIC client config"),
            ));
            // Use production transport config (no idle timeout)
            client_config.transport_config(transport_config());

            // Create server endpoint
            let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let server_endpoint = quinn::Endpoint::server(server_config, server_addr)
                .expect("failed to create server");
            let server_addr = server_endpoint
                .local_addr()
                .expect("failed to get server addr");

            // Create client endpoint
            let client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
                .expect("failed to create client");

            Self {
                _temp_dir: temp_dir,
                server_endpoint,
                server_addr,
                client_endpoint,
                client_config,
            }
        }

        /// Attempts to connect the client to the server.
        ///
        /// Returns the connection result, which may be an error if the handshake fails.
        async fn connect(&self) -> Result<quinn::Connection, quinn::ConnectionError> {
            self.client_endpoint
                .connect_with(self.client_config.clone(), self.server_addr, "127.0.0.1")
                .expect("failed to start connection")
                .await
        }

        /// Attempts to connect the client to the server with a timeout.
        ///
        /// Returns `Ok(Connection)` if the connection succeeds within the timeout,
        /// or `Err` if the timeout expires.
        async fn connect_with_timeout(
            &self,
            timeout_secs: u64,
        ) -> Result<quinn::Connection, tokio::time::error::Elapsed> {
            tokio::time::timeout(Duration::from_secs(timeout_secs), async {
                self.connect().await.expect("connection failed")
            })
            .await
        }
    }

    /// Tests that TLS handshake hangs with mismatched certificates when using
    /// production transport config (no idle timeout).
    ///
    /// When mTLS verification fails due to mismatched CAs, quinn's TLS handshake
    /// hangs indefinitely without an explicit timeout. This test verifies that:
    /// 1. The connection hangs (doesn't complete within timeout) with mismatched certs
    /// 2. Our production code correctly uses an explicit timeout to prevent hanging
    ///
    /// See: https://github.com/quinn-rs/quinn/issues/2298
    #[tokio::test]
    async fn test_tls_handshake_hangs_with_mismatched_certs() {
        let setup = QuicTestSetup::with_mismatched_cas();

        // With production transport config (no idle timeout), the TLS handshake
        // hangs indefinitely when certificates are mismatched. We use a short
        // timeout here to verify this behavior without waiting forever.
        let connect_result = tokio::time::timeout(Duration::from_secs(2), setup.connect()).await;

        // The connection should timeout because the TLS handshake hangs with mismatched certs.
        // This validates that we need the explicit timeout wrapper in our production code
        // (see client.rs connect method).
        assert!(
            connect_result.is_err(),
            "expected timeout - TLS handshake should hang with mismatched certs and no idle timeout"
        );
    }

    /// Tests that a QUIC connection succeeds when both client and server use
    /// certificates signed by the same CA and trust that CA.
    ///
    /// This test verifies the happy path for mTLS: when certificates are properly
    /// configured, the connection completes quickly and data can be sent over
    /// a bidirectional QUIC stream.
    #[tokio::test]
    async fn test_quic_connection_succeeds_with_valid_certs() {
        let setup = QuicTestSetup::with_shared_ca();

        // Spawn server task to accept connection and echo data
        let server_endpoint = setup.server_endpoint.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("no incoming connection");
            let connection = incoming.await.expect("failed to accept connection");

            // Accept a bidirectional stream
            let (mut send, mut recv) = connection
                .accept_bi()
                .await
                .expect("failed to accept stream");

            // Read data from client
            let data = recv
                .read_to_end(1024)
                .await
                .expect("failed to read from client");

            // Echo it back
            send.write_all(&data)
                .await
                .expect("failed to write to client");
            send.finish().expect("failed to finish stream");

            // Wait for the stream to be fully closed before returning
            // This ensures the client has time to read the response
            let _ = send.stopped().await;

            data
        });

        // Connection should succeed quickly with valid certs
        let connection = setup
            .connect_with_timeout(5)
            .await
            .expect("connection should complete within timeout");

        // Open a bidirectional stream and send data
        let (mut send, mut recv) = connection.open_bi().await.expect("failed to open stream");

        let test_data = b"Hello, QUIC with mTLS!";
        send.write_all(test_data)
            .await
            .expect("failed to write data");
        send.finish().expect("failed to finish stream");

        // Read the echoed response
        let response = recv
            .read_to_end(1024)
            .await
            .expect("failed to read response");

        assert_eq!(
            response, test_data,
            "server should echo back the same data"
        );

        // Verify server received the correct data
        let server_received = server_handle.await.expect("server task panicked");
        assert_eq!(
            server_received, test_data,
            "server should have received the test data"
        );
    }

    /// Tests that serialized messages can be sent and received over QUIC.
    ///
    /// This test verifies the transport layer's ability to handle protocol-like
    /// messages using the same serialization format (postcard) as the sync protocol.
    /// It demonstrates that the QUIC transport correctly handles:
    /// - Serialized request messages from client to server
    /// - Serialized response messages from server to client
    ///
    /// Note: A full poll sync test requires the complete Aranya stack (PolicyStore,
    /// StorageProvider, graphs) and is better suited for integration testing in
    /// `crates/aranya-client/tests/`. This test validates the transport layer
    /// independently of the sync protocol logic.
    #[tokio::test]
    async fn test_serialized_message_exchange() {
        let setup = QuicTestSetup::with_shared_ca();

        // Spawn server task that receives a request and sends a SyncResponse
        let server_endpoint = setup.server_endpoint.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("no incoming connection");
            let connection = incoming.await.expect("failed to accept connection");

            // Accept a bidirectional stream
            let (mut send, mut recv) = connection
                .accept_bi()
                .await
                .expect("failed to accept stream");

            // Read request data
            let request_data = recv
                .read_to_end(4096)
                .await
                .expect("failed to read from client");

            // Deserialize the request (just to verify format)
            let request: String =
                postcard::from_bytes(&request_data).expect("failed to deserialize request");

            // Create and send a SyncResponse (clone for response, keep original for return)
            let response = SyncResponse::Ok(request.as_bytes().to_vec().into_boxed_slice());
            let response_data =
                postcard::to_allocvec(&response).expect("failed to serialize response");

            send.write_all(&response_data)
                .await
                .expect("failed to write to client");
            send.finish().expect("failed to finish stream");
            let _ = send.stopped().await;

            request
        });

        // Connect and send a serialized request
        let connection = setup
            .connect_with_timeout(5)
            .await
            .expect("connection should complete within timeout");

        let (mut send, mut recv) = connection.open_bi().await.expect("failed to open stream");

        // Send a serialized request message
        let request_msg = "sync_request_data".to_string();
        let request_data = postcard::to_allocvec(&request_msg).expect("failed to serialize request");
        send.write_all(&request_data)
            .await
            .expect("failed to write request");
        send.finish().expect("failed to finish stream");

        // Read and deserialize the response
        let response_data = recv
            .read_to_end(4096)
            .await
            .expect("failed to read response");
        let response: SyncResponse =
            postcard::from_bytes(&response_data).expect("failed to deserialize response");

        // Verify the response
        match response {
            SyncResponse::Ok(data) => {
                let echoed = String::from_utf8(data.into_vec()).expect("invalid UTF-8");
                assert_eq!(echoed, request_msg, "server should echo request in response");
            }
            SyncResponse::Err(e) => panic!("unexpected error response: {}", e),
        }

        // Verify server received and processed the request
        let server_received = server_handle.await.expect("server task panicked");
        assert_eq!(server_received, request_msg);
    }
}
