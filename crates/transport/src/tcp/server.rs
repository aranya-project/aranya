//! TCP server.

use std::{
    collections::BTreeMap,
    io::{self, ErrorKind},
    net::SocketAddr,
    time::Duration,
};

use anyhow::Result;
use tokio::{
    io::{AsyncWriteExt, Interest},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::sleep,
};
use tracing::{debug, instrument};

use crate::Transport;

type StreamSend = mpsc::Sender<(SocketAddr, TcpStream)>;
type StreamRecv = mpsc::Receiver<(SocketAddr, TcpStream)>;

/// TCP server transport.
pub struct TcpTransport {
    pub streams: BTreeMap<SocketAddr, TcpStream>,
    rx: StreamRecv,
}

impl Transport for TcpTransport {
    /// Waits for transport to be readable.
    #[instrument(skip_all)]
    async fn readable(&mut self) -> io::Result<()> {
        loop {
            self.accept_incoming().await?;

            for (addr, stream) in &self.streams {
                debug!(?addr, "checking if readable");
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
    async fn try_recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.accept_incoming().await?;

        for (addr, stream) in &self.streams {
            let n = match stream.try_read(buf) {
                Ok(n) => n,
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    return Err(err);
                }
                Err(err) => {
                    debug!(?err, ?addr, "unable to read");
                    return Err(err);
                }
            };
            if n > 0 {
                debug!(?n, ?addr, "read bytes");
                return Ok((n, *addr));
            }
        }
        Err(io::Error::new(ErrorKind::Other, "failed to receive from"))
    }

    /// Send data via transport.
    #[instrument(skip_all)]
    async fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        debug!("accept_incoming");
        self.accept_incoming().await?;

        debug!(?addr, "looking up stream");
        if let Some(stream) = self.streams.get_mut(&addr) {
            debug!(?addr, n = buf.len(), "sending bytes");
            match stream.write_all(buf).await {
                Ok(_) => {
                    stream.shutdown().await?;
                    return Ok(buf.len());
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    return Err(err);
                }
                Err(err) => {
                    debug!(?err, ?addr, "unable to read");
                    return Err(err);
                }
            }
        }
        Err(io::Error::new(ErrorKind::Other, "failed to send to addr"))
    }
}

impl TcpTransport {
    #[instrument(skip_all)]
    pub async fn new(addr: SocketAddr) -> Result<(Self, TcpServer)> {
        let (tx, rx) = mpsc::channel(256);
        let server = TcpServer::new(addr, tx).await?;
        Ok((
            Self {
                streams: BTreeMap::new(),
                rx,
            },
            server,
        ))
    }

    #[instrument(skip_all)]
    pub async fn accept_incoming(&mut self) -> io::Result<()> {
        while !self.rx.is_empty() {
            debug!("accepting connection");
            if let Some((addr, stream)) = self.rx.recv().await {
                self.streams.insert(addr, stream);
                debug!(n = self.streams.len(), "total streams");
            }
        }
        Ok(())
    }
}

/// TcpServer that accepts incoming client connections.
pub struct TcpServer {
    listener: TcpListener,
    tx: StreamSend,
}

impl TcpServer {
    /// Create a new TCP server.
    #[instrument(skip_all)]
    pub async fn new(addr: SocketAddr, tx: StreamSend) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        debug!(?addr, "tcp server bound to");
        Ok(Self { listener, tx })
    }

    /// Run the TCP server task to accept incoming client connections.
    #[instrument(skip_all)]
    pub async fn run(&mut self) -> Result<()> {
        debug!("tcp server running");
        loop {
            let (stream, addr) = self.listener.accept().await?;
            debug!(?addr, "tcp server accepted connection");
            self.tx.send((addr, stream)).await?;
        }
    }

    // TODO: construct TCP transport from existing socket.

    /// Local server address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}
