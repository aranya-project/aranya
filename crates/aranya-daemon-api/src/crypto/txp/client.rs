use std::{borrow::Borrow as _, fmt};

use aranya_crypto::{
    dangerous::spideroak_crypto::{
        aead::Aead,
        hpke::{HpkeError, Seq},
    },
    CipherSuite, Csprng,
};
use buggy::BugExt;
use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};
use tokio::{io, net::UnixStream, sync::mpsc};
use tokio_util::codec::{Framed, FramedRead, FramedWrite, LengthDelimitedCodec};

use super::{
    ctx::{Ctx, Encap, OpenCtx, SealCtx},
    other, ClientMsg, OwnedReadHalf, OwnedWriteHalf, Rekey, ServerMsg, Side,
};
use crate::crypto::PublicApiKey;

/// Creates a client-side transport.
pub fn client<CS: CipherSuite, R>(
    io: UnixStream,
    codec: LengthDelimitedCodec,
    rng: R,
    pk: PublicApiKey<CS>,
    info: &[u8],
) -> ClientConn<CS, R> {
    ClientConn {
        inner: Framed::new(io, codec),
        rng,
        pk,
        info: Box::from(info),
        ctx: None,
        rekeys: 0,
    }
}

/// An encrypted client connection, created by [`client`].
pub struct ClientConn<CS: CipherSuite, R> {
    /// The underlying length-delimited transport.
    inner: Framed<UnixStream, LengthDelimitedCodec>,
    /// For rekeying.
    rng: R,
    /// The server's public key.
    pk: PublicApiKey<CS>,
    /// The "info" parameter when rekeying.
    info: Box<[u8]>,
    /// HPKE encryption context. Set on first send, updated on rekey.
    pub(super) ctx: Option<Ctx<CS>>,
    /// The number of times we've rekeyed, including the initial keying.
    ///
    /// Mostly for debugging purposes.
    pub(super) rekeys: usize,
}

impl<CS: CipherSuite, R: Csprng> ClientConn<CS, R> {
    pub fn into_split(self) -> (ClientReader<CS>, ClientWriter<CS, R>) {
        let (read, write) = self.inner.into_inner().into_split();
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(usize::MAX)
            .new_codec();

        let (open_tx, open_rx) = mpsc::unbounded_channel();
        let (seal, open) = match self.ctx {
            Some(ctx) => {
                let (s, o) = ctx.into_parts();
                (Some(s), Some(o))
            }
            None => (None, None),
        };

        let reader = ClientReader {
            inner: FramedRead::new(read, codec.clone()),
            open,
            open_rx,
        };

        let writer = ClientWriter {
            inner: FramedWrite::new(write, codec),
            seal,
            rng: self.rng,
            pk: self.pk,
            info: self.info,
            rekeys: self.rekeys,
            open_tx,
        };

        (reader, writer)
    }

    /// Send a message to the server.
    ///
    /// Handles rekeying automatically before sending.
    pub async fn send<T: Serialize>(&mut self, item: T) -> io::Result<()> {
        if self.need_rekey() {
            let enc = self.rekey().map_err(other)?;
            let rekey_msg = ClientMsg::Rekey(Rekey {
                enc: Bytes::from(enc.borrow().to_vec()),
            });
            super::frame_send(&mut self.inner, rekey_msg).await?;
        }

        let ctx = self
            .ctx
            .as_mut()
            .assume("`self.ctx` should be `Some`")
            .map_err(other)?;
        let data = ctx.encrypt(&item)?;
        super::frame_send(&mut self.inner, ClientMsg::Data(data)).await
    }

    /// Receive a message from the server.
    ///
    /// Returns `Ok(None)` if the connection was closed.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
        let Some(ServerMsg::Data(data)) = super::frame_recv(&mut self.inner).await? else {
            return Ok(None);
        };
        let ctx = self
            .ctx
            .as_mut()
            .assume("`self.ctx` should be `Some`")
            .map_err(other)?;
        let item = ctx.decrypt(data)?;
        Ok(Some(item))
    }

    /// Checks whether we need to generate a new HPKE encryption context.
    fn need_rekey(&self) -> bool {
        let Some(ctx) = self.ctx.as_ref() else {
            return true;
        };
        // To prevent us from reaching the end of the sequence, rekey when we're halfway there.
        let max = Seq::max::<<CS::Aead as Aead>::NonceSize>();
        let seq = ctx.seal.seq().to_u64();
        seq >= max / 2
    }

    /// Generates a new HPKE encryption context and returns the resulting peer encapsulation.
    fn rekey(&mut self) -> Result<Encap<CS>, HpkeError> {
        let (ctx, enc) = Ctx::client(&mut self.rng, &self.pk, &self.info)?;
        self.ctx = Some(ctx);
        // Rekeying takes so long (relatively speaking, anyway) that this should never overflow.
        self.rekeys = self
            .rekeys
            .checked_add(1)
            .assume("rekey count should not overflow")?;
        Ok(enc)
    }
}

impl<CS: CipherSuite, R> fmt::Debug for ClientConn<CS, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConn")
            .field("pk", &self.pk)
            .field("info", &self.info)
            .field("ctx", &self.ctx)
            .field("rekeys", &self.rekeys)
            .finish_non_exhaustive()
    }
}

/// Read hald of a client connection.
///
/// Receives and decrypts messages from the server. Listens for open context updates from the
/// [`ClientWriter`] due to rekeying.
pub struct ClientReader<CS: CipherSuite> {
    inner: FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
    open: Option<OpenCtx<CS>>,
    open_rx: mpsc::UnboundedReceiver<OpenCtx<CS>>,
}

impl<CS: CipherSuite> ClientReader<CS> {
    /// Receive a message from the server.
    ///
    /// Before decrypting, drains any pending open context updates from the writer (indicating a
    /// rekey occurred).
    pub async fn recv<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
        // Pick up any new open context from the writer.
        // Last one wins if multiple rekeys happened between reads.
        while let Ok(new_open) = self.open_rx.try_recv() {
            self.open = Some(new_open);
        }

        let Some(ServerMsg::Data(data)) = super::frame_recv_read(&mut self.inner).await? else {
            return Ok(None);
        };

        let ctx = self
            .open
            .as_mut()
            .assume("`self.open` should be `Some`")
            .map_err(other)?;
        let item = super::open::<CS, _>(ctx, data, Side::Server)?;
        Ok(Some(item))
    }
}

impl<CS: CipherSuite> fmt::Debug for ClientReader<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientReader")
            .field("inner", &self.inner)
            .field("open_rx", &self.open_rx)
            .finish_non_exhaustive()
    }
}

/// Writer half of a client connection.
///
/// Encrypts and sends messages to the server. Handles rekeying and notifies the [`ClientReader`] of
/// any new open contexts.
pub struct ClientWriter<CS: CipherSuite, R> {
    inner: FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
    seal: Option<SealCtx<CS>>,
    rng: R,
    pk: PublicApiKey<CS>,
    info: Box<[u8]>,
    rekeys: usize,
    open_tx: mpsc::UnboundedSender<OpenCtx<CS>>,
}

impl<CS: CipherSuite, R: Csprng> ClientWriter<CS, R> {
    /// Send a message to the server.
    ///
    /// Rekeys automatically when the seal sequence number approaches the AEAD nonce space limit.
    ///
    /// When rekeying, a new HPKE context is created, the seal context is kept, the open context is
    /// send to the [`ClientReader`], a `Rekey` message is sent to the server, and then data is
    /// encrypted using the new seal context.
    pub async fn send<T: Serialize>(&mut self, item: T) -> io::Result<()> {
        if self.need_rekey() {
            self.do_rekey().await?;
        }

        let ctx = self
            .seal
            .as_mut()
            .assume("seal should be set after rekey")
            .map_err(other)?;
        let data = super::seal::<CS, _>(ctx, &item, Side::Client)?;
        super::frame_send_write(&mut self.inner, ClientMsg::Data(data)).await
    }

    /// Checks whether we need to generate a new HPKE encryption context.
    fn need_rekey(&self) -> bool {
        let Some(seal) = self.seal.as_ref() else {
            return true;
        };
        // To prevent us from reaching the end of the sequence, rekey when we're halfway there.
        let max = Seq::max::<<CS::Aead as Aead>::NonceSize>();
        let seq = seal.seq().to_u64();
        seq >= max / 2
    }

    /// Generates a new HPKE encryption context, sets its seal context, and sends the open context
    /// to a [`ClientReader`].
    async fn do_rekey(&mut self) -> io::Result<()> {
        let (ctx, enc) = Ctx::client(&mut self.rng, &self.pk, &self.info).map_err(other)?;
        let (new_seal, new_open) = ctx.into_parts();
        self.seal = Some(new_seal);
        let _ = self.open_tx.send(new_open);
        // Rekeying takes so long (relatively speaking, anyway) that this should never overflow.
        self.rekeys = self
            .rekeys
            .checked_add(1)
            .assume("rekey count should not overflow")
            .map_err(other)?;
        let rekey_msg = ClientMsg::Rekey(Rekey {
            enc: Bytes::from(enc.borrow().to_vec()),
        });
        super::frame_send_write(&mut self.inner, rekey_msg).await
    }
}

impl<CS: CipherSuite, R> fmt::Debug for ClientWriter<CS, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientWriter")
            .field("inner", &self.inner)
            .field("pk", &self.pk)
            .field("info", &self.info)
            .field("rekeys", &self.rekeys)
            .field("open_tx", &self.open_tx)
            .finish_non_exhaustive()
    }
}
