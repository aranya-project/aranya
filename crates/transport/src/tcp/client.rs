//! TCP client.

use std::{
    collections::{btree_map::Entry::Vacant, BTreeMap},
    io::{self, ErrorKind, Write},
    net::SocketAddr,
    time::Duration,
};

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest},
    net::TcpStream,
    time::sleep,
};
use tracing::{debug, error, instrument};

use crate::Transport;

/// TCP client transport.
pub struct TcpClient {
    streams: BTreeMap<SocketAddr, TcpStream>,
}

impl Transport for TcpClient {
    /// Waits for transport to be readable.
    #[instrument(skip_all)]
    async fn readable(&mut self) -> io::Result<()> {
        loop {
            for (addr, stream) in &self.streams {
                let ready = stream.ready(Interest::READABLE).await?;
                if ready.is_readable() {
                    debug!(?addr, "is readable");
                    return Ok(());
                }
            }

            sleep(Duration::from_millis(10)).await;
        }
    }

    /// Try to receive data via transport.
    #[instrument(skip_all)]
    async fn try_recv_from(&mut self, mut buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        for (addr, stream) in &mut self.streams {
            let mut v = Vec::new();
            stream.read_to_end(&mut v).await?;
            if !v.is_empty() {
                debug!(?addr, len = v.len(), "received bytes");
                buf.write_all(&v)?;
                return Ok((v.len(), *addr));
            }
        }
        Err(io::Error::new(
            ErrorKind::Other,
            "failed to receive from addr",
        ))
    }

    /// Send data via transport.
    #[instrument(skip_all)]
    async fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if let Vacant(e) = self.streams.entry(addr) {
            debug!(?addr, "tcp client attempting to connect");
            let stream = TcpStream::connect(addr).await?;
            debug!(?addr, "tcp client adding new stream");
            e.insert(stream);
        }

        if let Some(stream) = self.streams.get_mut(&addr) {
            let n = buf.len();
            debug!(?n, ?addr, "sending bytes");
            match stream.write_all(buf).await {
                Ok(n) => {
                    stream.shutdown().await?;
                    n
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    return Err(err);
                }
                Err(err) => {
                    debug!(?err, ?addr, "unable to write");
                    return Err(err);
                }
            };
            return Ok(n);
        }
        error!("failed to send to");
        Err(io::Error::new(ErrorKind::Other, "failed to send to"))
    }
}

impl TcpClient {
    /// Create new TCP client.
    #[instrument(skip_all)]
    pub fn new() -> Result<Self> {
        Ok(Self {
            streams: BTreeMap::new(),
        })
    }

    /// Try to receive data via transport from a specified address.
    // TODO: use this in try_recv_from.
    #[instrument(skip_all)]
    pub async fn try_recv_from_addr(
        &mut self,
        mut buf: &mut [u8],
        addr: SocketAddr,
    ) -> io::Result<(usize, SocketAddr)> {
        if let Some(stream) = self.streams.get_mut(&addr) {
            debug!(?addr, "found stream");
            let mut v = Vec::new();
            stream.read_to_end(&mut v).await?;
            if !v.is_empty() {
                debug!(?addr, len = v.len(), buf_len = buf.len(), "received bytes");
                buf.write_all(&v)?;
                self.streams.remove(&addr);
                return Ok((v.len(), addr));
            }
        }
        Err(io::Error::new(
            ErrorKind::Other,
            "failed to receive from addr",
        ))
    }
}
