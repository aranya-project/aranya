//! Lightweight TCP client and server for demo purposes.
//! It is the user's responsibility to send data in the order each application expects.

use anyhow::{Context, Result};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

/// Simple TCP server for demo purposes.
#[derive(Debug)]
pub struct TcpServer {
    listener: TcpListener,
}

impl TcpServer {
    /// Bind server to listen on address.
    pub async fn bind(addr: Addr) -> Result<Self> {
        let listener = TcpListener::bind(addr.to_socket_addrs()).await?;
        Ok(Self { listener })
    }

    /// Recv data from TCP server.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let (mut stream, _addr) = self.listener.accept().await?;
        let _ = stream
            .read_to_end(&mut data)
            .await
            .expect("expected to read_to_end on tcp stream");
        Ok(data)
    }
}

/// Simple TCP client for demo purposes.
#[derive(Debug)]
pub struct TcpClient {
    stream: TcpStream,
}

impl TcpClient {
    /// Connect to peer's TCP server.
    pub async fn connect(peer: Addr) -> Result<Self> {
        let stream = (|| TcpStream::connect(peer.to_socket_addrs()))
            .retry(ExponentialBuilder::default())
            .await
            .with_context(|| "unable to connect to TCP server")?;
        Ok(Self { stream })
    }

    /// Send data to peer's TCP server.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.stream
            .write_all(data)
            .await
            .with_context(|| "unable to send data to peer via TCP stream")?;
        self.stream
            .flush()
            .await
            .with_context(|| "unable to flush TCP stream")?;
        Ok(())
    }
}
