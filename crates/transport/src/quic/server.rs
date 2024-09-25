//! Quic transport data multiplexer.

use std::{
    io::{self},
    net::{SocketAddr, UdpSocket},
    path::Path,
    sync::Arc,
};

use anyhow::{bail, Context, Result};
pub use quinn::ServerConfig;
use quinn::{Connecting, Endpoint, EndpointConfig, StreamId};
use rcgen::{CertificateParams, CertificateSigningRequest};
use rustls::{Certificate, PrivateKey};
use serde::Serialize;
use tokio::fs;
use tracing::{debug, error, instrument};

/// Aranya QUIC server.
pub struct QuicServer {
    /// Server's socket endpoint.
    pub endpoint: Endpoint,
}

impl QuicServer {
    /// Creates a `QuicServer` using `socket`.
    pub fn new(mut srv_cfg: ServerConfig, sock: UdpSocket) -> Result<Self> {
        // TODO(eric): why are we setting this to zero?
        Arc::get_mut(&mut srv_cfg.transport)
            .context("unable to get `TransportConfig`")?
            .max_concurrent_uni_streams(0u8.into());

        let runtime = quinn::default_runtime().context("unable to find async runtime")?;
        let endpoint = Endpoint::new(EndpointConfig::default(), Some(srv_cfg), sock, runtime)?;
        Ok(Self { endpoint })
    }

    /// Creates a `QuicServer` listening at `addr`.
    pub fn listen(srv_cfg: ServerConfig, addr: SocketAddr) -> Result<Self> {
        let sock = UdpSocket::bind(addr)?;
        Self::new(srv_cfg, sock)
    }

    /// Returns the address that the server is listening on.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Accepts the next incoming stream.
    #[instrument(skip_all)]
    pub async fn accept(&mut self) -> Option<Result<Stream>> {
        let conn = self.endpoint.accept().await?;
        match Self::open_streams(conn).await {
            Ok(stream) => Some(Ok(stream)),
            // TODO(eric): handle this?
            // Err(ConnectionError::ApplicationClosed { .. }) => None,
            Err(err) => Some(Err(err)),
        }
    }

    #[instrument(skip_all)]
    async fn open_streams(conn: Connecting) -> Result<Stream> {
        let conn = conn.await?;
        let (send, recv) = conn.accept_bi().await?;
        Ok(Stream {
            send: SendStream(send),
            recv: RecvStream(recv),
            addr: conn.remote_address(),
        })
    }

    /// Accepts incoming connections to server.
    ///
    /// This method should be called in a loop:
    ///
    /// ```ignore
    /// let mut server = QuicServer::new(...);
    /// loop {
    ///     if let Err(err) = server.next().await {
    ///         // do something with `err`
    ///     }
    /// }
    /// ```
    #[instrument(skip_all)]
    pub async fn next(&mut self) -> Result<()> {
        if let Some(incoming) = self.accept().await {
            match incoming {
                Ok(stream) => {
                    debug!(addr = %stream.addr, "received stream");
                    return Ok(());
                }
                Err(err) => {
                    error!(err = %err, "stream failure");
                    bail!("stream failure: {}", err)
                }
            }
        }
        debug!("no incoming connection");
        bail!("no incoming connections")
    }
}

impl Drop for QuicServer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"done");
    }
}

/// Quic stream.
pub struct Stream {
    /// send stream.
    pub send: SendStream,
    /// recv stream.
    pub recv: RecvStream,
    /// peer socket address.
    pub addr: SocketAddr,
}

/// A server's TLS configuration.
#[derive(Clone)]
pub struct ServerTlsConfig {
    cert: Certificate,
    key: PrivateKey,
}

impl ServerTlsConfig {
    /// Reads the TLS configuration from disk.
    pub async fn load<P>(public_cert: P, private_key: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let (cert, key) = tokio::try_join!(fs::read(&public_cert), fs::read(&private_key))
            .context("unable to read TLS cert and/or key")?;
        // TODO(eric): parse/verify DER before returning it.
        Ok(Self {
            cert: Certificate(cert),
            key: PrivateKey(key),
        })
    }

    /// Generates a TLS certificate signed by `ca`.
    pub fn generate(ca: &rcgen::Certificate, addr: &SocketAddr) -> Result<Self> {
        let params = CertificateParams::new(vec![addr.ip().to_string()]);
        let cert = rcgen::Certificate::from_params(params)?;
        let csr = CertificateSigningRequest::from_der(&cert.serialize_request_der()?)?;
        Ok(Self {
            cert: Certificate(csr.serialize_der_with_signer(ca)?),
            key: PrivateKey(cert.serialize_private_key_der()),
        })
    }

    /// Creates a [`ServerConfig`] from the TLS configuration.
    pub fn into_server_config(self) -> Result<ServerConfig> {
        let cfg = ServerConfig::with_single_cert(vec![self.cert], self.key)?;
        Ok(cfg)
    }
}

/// A bidirectional QUIC stream.
pub struct RecvStream(quinn::RecvStream);

impl RecvStream {
    /// Returns the identity of the stream.
    pub fn id(&self) -> StreamId {
        self.0.id()
    }

    /// Reads the entire stream.
    #[instrument(skip_all, fields(stream = %self.id()))]
    pub async fn recv(&mut self) -> Result<Box<[u8]>> {
        let buf = self.0.read_to_end(usize::MAX).await?;
        Ok(buf.into())
    }
}

/// A bidirectional QUIC stream.
pub struct SendStream(quinn::SendStream);

impl SendStream {
    /// Returns the identity of the stream.
    pub fn id(&self) -> StreamId {
        self.0.id()
    }

    /// Writes data to the connection.
    #[instrument(skip_all, fields(stream = %self.id()))]
    pub async fn send(mut self, data: impl Serialize) -> Result<()> {
        let buf = postcard::to_allocvec(&data)?;
        debug!(len = buf.len(), "sending response");
        self.0
            .write_all(&buf)
            .await
            .context("unable to write response")?;
        self.0.finish().await.context("finish failed")?;
        Ok(())
    }
}
