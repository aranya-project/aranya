use std::{fmt, sync::Arc};

use aranya_crypto::CipherSuite;
use buggy::BugExt;
use futures_util::{Stream, StreamExt as _};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io::{self},
    net::UnixStream,
    sync::mpsc,
};
use tokio_util::codec::{Framed, FramedRead, FramedWrite, LengthDelimitedCodec};

use super::{
    ctx::{Ctx, OpenCtx, SealCtx},
    other, ClientMsg, OwnedReadHalf, OwnedWriteHalf, ServerMsg, Side,
};
use crate::crypto::ApiKey;

/// Creates a server-side transport.
pub fn server<L, CS: CipherSuite>(
    listener: L,
    codec: LengthDelimitedCodec,
    sk: ApiKey<CS>,
    info: &[u8],
) -> Server<L, CS> {
    Server {
        listener,
        codec,
        sk: Arc::new(sk),
        info: Arc::from(info),
    }
}

/// Accepts incoming connections and wraps them in [`ServerConn`]s, created by [`server`].
pub struct Server<L, CS: CipherSuite> {
    listener: L,
    codec: LengthDelimitedCodec,
    /// The server's secret key.
    sk: Arc<ApiKey<CS>>,
    /// The "info" parameter when rekeying.
    info: Arc<[u8]>,
}

impl<L, CS: CipherSuite> Server<L, CS>
where
    L: Stream<Item = io::Result<UnixStream>> + Unpin,
{
    /// Accept the next incoming connection.
    ///
    /// Returns `None` when the listener is exhausted.
    pub async fn accept(&mut self) -> Option<io::Result<ServerConn<CS>>> {
        let io = match self.listener.next().await? {
            Ok(io) => io,
            Err(err) => return Some(Err(err)),
        };
        let conn = ServerConn {
            inner: Framed::new(io, self.codec.clone()),
            sk: Arc::clone(&self.sk),
            info: Arc::clone(&self.info),
            ctx: None,
        };
        Some(Ok(conn))
    }
}

impl<L, CS: CipherSuite> fmt::Debug for Server<L, CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("sk", &self.sk)
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// An encrypted server connection, created by [`Server::accept`].
pub struct ServerConn<CS: CipherSuite> {
    /// The underlying length-delimited transport.
    inner: Framed<UnixStream, LengthDelimitedCodec>,
    /// The server's secret key.
    sk: Arc<ApiKey<CS>>,
    /// The "info" parameter when rekeying.
    info: Arc<[u8]>,
    /// The HPKE encryption context.
    ///
    /// This is set to `Some` after the client sends the first `Rekey` message.
    ///
    /// It is periodically updated via rekeying in order to keep the keys fresh.
    pub(super) ctx: Option<Ctx<CS>>,
}

impl<CS: CipherSuite> ServerConn<CS> {
    pub fn into_split(self) -> (ServerReader<CS>, ServerWriter<CS>) {
        let (read, write) = self.inner.into_inner().into_split();
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(usize::MAX)
            .new_codec();

        let (seal_tx, seal_rx) = mpsc::unbounded_channel();

        let (seal, open) = match self.ctx {
            Some(ctx) => {
                let (s, o) = ctx.into_parts();
                (Some(s), Some(o))
            }
            None => (None, None),
        };

        let reader = ServerReader {
            inner: FramedRead::new(read, codec.clone()),
            open,
            sk: self.sk,
            info: self.info,
            seal_tx,
        };

        let writer = ServerWriter {
            inner: FramedWrite::new(write, codec),
            seal,
            seal_rx,
        };

        (reader, writer)
    }

    /// Send a message to the client.
    pub async fn send<T: Serialize>(&mut self, item: T) -> io::Result<()> {
        let ctx = self
            .ctx
            .as_mut()
            .assume("`self.ctx` should be `Some`")
            .map_err(other)?;
        let data = ctx.encrypt(&item)?;
        super::frame_send(&mut self.inner, ServerMsg::Data(data)).await
    }

    /// Receive a message from the client.
    ///
    /// Handles rekey messages automatically.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
        // Loop to skip past control messages (rekeying)
        loop {
            let Some(msg) = super::frame_recv(&mut self.inner).await? else {
                return Ok(None);
            };
            match msg {
                ClientMsg::Data(data) => {
                    let ctx = self
                        .ctx
                        .as_mut()
                        .assume("`self.ctx` should be `Some`")
                        .map_err(other)?;
                    let item = ctx.decrypt(data)?;
                    return Ok(Some(item));
                }
                ClientMsg::Rekey(rekey) => {
                    let ctx = Ctx::server(&self.sk, &self.info, &rekey.enc).map_err(other)?;
                    self.ctx = Some(ctx);
                }
            }
        }
    }
}

impl<CS: CipherSuite> fmt::Debug for ServerConn<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConn")
            .field("sk", &self.sk)
            .field("ctx", &self.ctx)
            .finish_non_exhaustive()
    }
}

pub struct ServerReader<CS: CipherSuite> {
    inner: FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
    open: Option<OpenCtx<CS>>,
    /// Server's secret key, needed to process Rekey messages.
    sk: Arc<ApiKey<CS>>,
    /// HPKE info parameter.
    info: Arc<[u8]>,
    /// Sends new seal contexts to the writer after rekey.
    seal_tx: mpsc::UnboundedSender<SealCtx<CS>>,
}

impl<CS: CipherSuite> ServerReader<CS> {
    pub async fn recv<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
        loop {
            let Some(msg) = super::frame_recv_read(&mut self.inner).await? else {
                return Ok(None);
            };
            match msg {
                ClientMsg::Data(data) => {
                    let ctx = self
                        .open
                        .as_mut()
                        .assume("`self.ctx` should be `Some`")
                        .map_err(other)?;
                    let item = super::open::<CS, _>(ctx, data, Side::Client)?;
                    return Ok(Some(item));
                }
                ClientMsg::Rekey(rekey) => {
                    let new_ctx = Ctx::server(&self.sk, &self.info, &rekey.enc).map_err(other)?;
                    let (new_seal, new_open) = new_ctx.into_parts();
                    self.open = Some(new_open);
                    let _ = self.seal_tx.send(new_seal);
                }
            }
        }
    }
}

impl<CS: CipherSuite> fmt::Debug for ServerReader<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerReader")
            .field("inner", &self.inner)
            .field("sk", &self.sk)
            .field("info", &self.info)
            .field("seal_tx", &self.seal_tx)
            .finish_non_exhaustive()
    }
}

/// Write half of a server connection.
///
/// Encrypts and sends messages to the client. Listens for seal context updates from the
/// [`ServerReader`] due to rekeying.
pub struct ServerWriter<CS: CipherSuite> {
    inner: FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
    seal: Option<SealCtx<CS>>,
    seal_rx: mpsc::UnboundedReceiver<SealCtx<CS>>,
}

impl<CS: CipherSuite> ServerWriter<CS> {
    /// Send a message to the client.
    ///
    /// Before encrypting, drains any pending seal context updates from the reader (indicating a
    /// rekey occurred).
    pub async fn send<T: Serialize>(&mut self, item: T) -> io::Result<()> {
        // Pick up any new open context from the reader.
        // Last one wins if multiple rekeys happened between writes.
        while let Ok(new_seal) = self.seal_rx.try_recv() {
            self.seal = Some(new_seal);
        }

        let ctx = self
            .seal
            .as_mut()
            .assume("`self.seal` should be `Some`")
            .map_err(other)?;
        let data = super::seal::<CS, T>(ctx, &item, Side::Server)?;
        super::frame_send_write(&mut self.inner, ServerMsg::Data(data)).await
    }
}

impl<CS: CipherSuite> fmt::Debug for ServerWriter<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerWriter")
            .field("inner", &self.inner)
            .field("seal_rx", &self.seal_rx)
            .finish_non_exhaustive()
    }
}
