use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
pub use quinn::{ClientConfig, TransportConfig};
use quinn::{Endpoint, RecvStream, SendStream};
use serde::de::DeserializeOwned;
use tokio_retry::{
    strategy::{jitter, ExponentialBackoff},
    Retry,
};
use tracing::{debug, instrument};

/// QUIC client.
#[derive(Clone)]
pub struct QuicClient {
    endpoint: Endpoint,
    cfg: ClientConfig,
}

impl QuicClient {
    /// Creates a new QUIC client.
    pub fn new(cfg: ClientConfig) -> Result<Self> {
        Ok(QuicClient {
            endpoint: Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into())?,
            cfg,
        })
    }

    /// Creates a new QUIC client from existing endpoint.
    pub fn from_endpoint(cfg: ClientConfig, endpoint: Endpoint) -> Result<Self> {
        Ok(QuicClient { endpoint, cfg })
    }
}

impl QuicClient {
    /// Creates a connection with the peer at `addr`.
    #[instrument(skip(self))]
    pub async fn connect(&self, addr: &SocketAddr) -> Result<ClientStream> {
        let delay = ExponentialBackoff::from_millis(1).map(jitter).take(10);
        let host = addr.ip().to_string();
        let stream = Retry::spawn(delay, || {
            // TODO(eric): differentiate between transient and
            // fatal errors.
            ClientStream::open(&self.endpoint, self.cfg.clone(), addr, host.as_str())
        })
        .await?;
        Ok(stream)
    }
}

/// A bidirectional QUIC stream.
pub struct ClientStream {
    send: SendStream,
    recv: RecvStream,
}

impl ClientStream {
    pub(super) async fn open(
        endpoint: &Endpoint,
        cfg: ClientConfig,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<Self> {
        let conn = endpoint.connect_with(cfg, *addr, server_name)?.await?;
        let (send, recv) = conn.open_bi().await?;
        Ok(Self { send, recv })
    }

    /// Writes data to the connection and retrieves the response.
    #[instrument(skip_all, fields(stream = %self.send.id()))]
    pub async fn send<T>(mut self, data: &[u8]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        debug!(len = data.len(), "sending request");
        self.send
            .write_all(data)
            .await
            .context("unable to write request")?;
        self.send.finish().await.context("finish failed")?;

        // TODO(eric): this is pretty arbitrary. We should come
        // up with a better API for this. Ideally, we'd just tell
        // postcard to read bytes from `self.recv`. However,
        // `postcard::from_io` requires a buffer that's large
        // enough to read the largest data type. This is
        // borderline useless for types without a fixed size
        // (sequence types), like `Vec<u8>` since we don't
        // actually know their max size.
        const MAX: usize = 32 * 1024 * 1024;
        let resp = self
            .recv
            .read_to_end(MAX)
            .await
            .context("unable to read response")?;
        debug!(len = resp.len(), "got response");

        Ok(postcard::from_bytes(&resp)?)
    }

    /// Writes data to the connection.
    #[instrument(skip_all, fields(stream = %self.send.id()))]
    pub async fn send_bytes(mut self, buf: &[u8]) -> Result<()> {
        debug!(len = buf.len(), "sending request");
        self.send
            .write_all(buf)
            .await
            .context("unable to write request")?;
        self.send.finish().await.context("finish failed")?;
        Ok(())
    }
}
