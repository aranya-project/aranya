//! Encrypted tarpc [`Transport`]s.
//!
//! [`Transport`][tarpc::Transport]

use core::{
    borrow::Borrow,
    error, fmt,
    marker::PhantomData,
    pin::{pin, Pin},
    task::{Context, Poll},
};
use std::{iter, sync::Arc};

use aranya_crypto::{
    dangerous::spideroak_crypto::{
        aead::{Aead, Tag},
        hpke::{Hpke, HpkeError, Mode, OpenCtx, SealCtx, Seq},
        import::Import,
        kem::Kem,
    },
    CipherSuite, Csprng,
};
use buggy::BugExt;
use bytes::{Bytes, BytesMut};
use futures_util::{ready, Sink, Stream, TryStream};
use pin_project::pin_project;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub use tarpc::tokio_util::codec::length_delimited::{Builder, LengthDelimitedCodec};
use tarpc::{
    serde_transport::{self, Transport},
    tokio_serde::{formats::MessagePack, Deserializer, Serializer},
    tokio_util::codec::Framed,
};
use tokio::io::{self, AsyncRead, AsyncWrite};

use crate::crypto::{ApiKey, PublicApiKey};

fn other<E>(err: E) -> io::Error
where
    E: Into<Box<dyn error::Error + Send + Sync>>,
{
    io::Error::other(err)
}

type Encap<CS> = <<CS as CipherSuite>::Kem as Kem>::Encap;

/// HPKE encryption context.
///
/// The client creates one the first time it tries to write to
/// the server. It sends the HPKE peer encapsulation to the
/// server, then begins sending ciphertext.
///
/// The server creates one the first time it receives a HPKE peer
/// encapsulation from the client.
struct Ctx<CS: CipherSuite> {
    seal: SealCtx<<CS as CipherSuite>::Aead>,
    open: OpenCtx<<CS as CipherSuite>::Aead>,
}

impl<CS: CipherSuite> Ctx<CS> {
    // Contextual binding for exporting the server's encryption
    // key and nonce.
    const SERVER_KEY_CTX: &[u8] = b"aranya daemon api server seal key";
    const SERVER_NONCE_CTX: &[u8] = b"aranya daemon api server seal nonce";

    /// Creates the HPKE encryption context for the client.
    fn client<R: Csprng>(
        rng: &mut R,
        pk: &PublicApiKey<CS>,
        info: &[u8],
    ) -> Result<(Self, Encap<CS>), HpkeError> {
        let (enc, send) = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send(
            rng,
            Mode::Base,
            pk.as_inner(),
            iter::once(info),
        )?;
        // NB: These are the reverse of the server's keys.
        let (open_key, open_nonce) = {
            let key = send.export(Self::SERVER_KEY_CTX)?;
            let nonce = send.export(Self::SERVER_NONCE_CTX)?;
            (key, nonce)
        };
        let (seal_key, seal_nonce) = send
            .into_raw_parts()
            .assume("should be able to decompose `SendCtx`")?;

        let ctx = Self {
            seal: SealCtx::new(&seal_key, &seal_nonce, Seq::ZERO)?,
            open: OpenCtx::new(&open_key, &open_nonce, Seq::ZERO)?,
        };
        Ok((ctx, enc))
    }

    /// Creates the HPKE encryption context for the server.
    fn server(sk: &ApiKey<CS>, info: &[u8], enc: &[u8]) -> Result<Self, HpkeError> {
        let enc = Encap::<CS>::import(enc)?;

        let recv = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_recv(
            Mode::Base,
            &enc,
            sk.as_inner(),
            iter::once(info),
        )?;
        // NB: These are the reverse of the client's keys.
        let (seal_key, seal_nonce) = {
            let key = recv.export(Self::SERVER_KEY_CTX)?;
            let nonce = recv.export(Self::SERVER_NONCE_CTX)?;
            (key, nonce)
        };
        let (open_key, open_nonce) = recv
            .into_raw_parts()
            .assume("should be able to decompose `SendCtx`")?;

        Ok(Self {
            seal: SealCtx::new(&seal_key, &seal_nonce, Seq::ZERO)?,
            open: OpenCtx::new(&open_key, &open_nonce, Seq::ZERO)?,
        })
    }

    /// Serializes `item`, encrypts and authenticates the
    /// resulting bytes, and returns the ciphertext.
    ///
    /// `side` represents the current side performing the
    /// encryption.
    fn encrypt<Item, SinkItem>(&mut self, item: SinkItem, side: Side) -> io::Result<Data>
    where
        SinkItem: Serialize,
    {
        let codec = MessagePack::<Item, SinkItem>::default();
        let mut plaintext = BytesMut::from(pin!(codec).serialize(&item)?);
        let mut tag = BytesMut::from(&*Tag::<CS::Aead>::default());
        let ad = auth_data(self.seal.seq(), side);
        let seq = self
            .seal
            .seal_in_place(&mut plaintext, &mut tag, &ad)
            .map_err(other)?;
        Ok(Data {
            seq: seq.to_u64(),
            ciphertext: plaintext,
            tag: tag.freeze(),
        })
    }

    /// Decrypts and authenticates `data`, then deserializes the
    /// resulting plaintext and returns the resulting `Item`.
    ///
    /// `side` represents the side that created `data`.
    fn decrypt<Item, SinkItem>(&mut self, data: Data, side: Side) -> io::Result<Item>
    where
        Item: DeserializeOwned,
    {
        let Data {
            seq,
            mut ciphertext,
            tag,
        } = data;
        let ad = auth_data(Seq::new(seq), side);
        self.open
            .open_in_place_at(&mut ciphertext, &tag, &ad, Seq::new(seq))
            .map_err(other)?;
        let codec = MessagePack::<Item, SinkItem>::default();
        let item = pin!(codec).deserialize(&ciphertext)?;
        Ok(item)
    }
}

impl<CS: CipherSuite> fmt::Debug for Ctx<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ctx").finish_non_exhaustive()
    }
}

/// Generates the AD for encryption/decryption.
///
/// We include the sequence number in the AD per the advice in
/// [RFC 9180] section 9.7.1.
///
/// [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
fn auth_data(seq: Seq, side: Side) -> [u8; 8 + 14] {
    let base = match side {
        Side::Server => b"server base ad",
        Side::Client => b"client base ad",
    };

    // ad = seq || base
    let mut ad = [0; 8 + 14];
    ad[..8].copy_from_slice(&seq.to_u64().to_le_bytes());
    ad[8..].copy_from_slice(base);
    ad
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Side {
    Server,
    Client,
}

/// Creates a client-side transport.
pub fn client<S, R, CS, Item, SinkItem>(
    io: S,
    codec: LengthDelimitedCodec,
    rng: R,
    pk: PublicApiKey<CS>,
    info: &[u8],
) -> ClientConn<S, R, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    CS: CipherSuite,
{
    ClientConn {
        inner: serde_transport::new(Framed::new(io, codec), MessagePack::default()),
        rng,
        pk,
        info: Box::from(info),
        ctx: None,
        rekeys: 0,
        _marker: PhantomData,
    }
}

/// An encrypted [`Transport`][tarpc::Transport] for the client.
///
/// It is created by [`client`].
#[pin_project]
pub struct ClientConn<S, R, CS, Item, SinkItem>
where
    CS: CipherSuite,
{
    /// The underlying transport.
    #[pin]
    inner: Transport<S, ServerMsg, ClientMsg, MessagePack<ServerMsg, ClientMsg>>,
    /// For rekeying.
    rng: R,
    /// The server's public key.
    pk: PublicApiKey<CS>,
    /// The "info" parameter when rekeying.
    info: Box<[u8]>,
    /// This is set to `Some` the first time the conn (as
    /// a `Sink`) is polled for readiness.
    ///
    /// It is periodically updated via rekeying in order to keep
    /// the keys fresh.
    ctx: Option<Ctx<CS>>,
    /// The number of times we've rekeyed, including the initial
    /// keying.
    ///
    /// Mostly for debugging purposes.
    rekeys: usize,
    _marker: PhantomData<fn() -> (Item, SinkItem)>,
}

impl<S, R, CS, Item, SinkItem> ClientConn<S, R, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    CS: CipherSuite,
    SinkItem: Serialize,
{
    /// Serializes `item`, encrypts and authenticates the
    /// resulting bytes, and returns the ciphertext.
    ///
    /// It is an error if `self.ctx` has not yet been
    /// initialized.
    fn encrypt(&mut self, item: SinkItem) -> io::Result<Data> {
        self.ctx
            .as_mut()
            .assume("`self.ctx` should be `Some`")
            .map_err(other)?
            .encrypt::<Item, SinkItem>(item, Side::Client)
            .map_err(other)
    }
}

impl<S, R, CS, Item, SinkItem> ClientConn<S, R, CS, Item, SinkItem>
where
    CS: CipherSuite,
    Item: DeserializeOwned,
{
    /// Decrypts and authenticates `data`, then deserializes the
    /// resulting plaintext and returns the resulting `Item`.
    ///
    /// It is an error if `self.ctx` has not yet been
    /// initialized.
    fn decrypt(&mut self, data: Data) -> io::Result<Item> {
        self.ctx
            .as_mut()
            .assume("`self.ctx` should be `Some`")
            .map_err(other)?
            .decrypt::<Item, SinkItem>(data, Side::Server)
            .map_err(other)
    }
}

impl<S, R, CS, Item, SinkItem> ClientConn<S, R, CS, Item, SinkItem>
where
    R: Csprng,
    CS: CipherSuite,
{
    /// Returns `Some` with the `Rekey` message to send to the
    /// server if we need to rekey, or `None` otherwise.
    fn try_rekey(&mut self) -> Result<Option<ClientMsg>, HpkeError> {
        if !self.need_rekey() {
            return Ok(None);
        }
        let enc = self.rekey()?;
        let msg = ClientMsg::Rekey(Rekey {
            enc: Bytes::from(enc.borrow().to_vec()),
        });
        Ok(Some(msg))
    }

    /// Reports whether we need to generate a new HPKE encryption
    /// context.
    fn need_rekey(&self) -> bool {
        let Some(ctx) = self.ctx.as_ref() else {
            return true;
        };
        // To prevent us from reaching the end of the sequence,
        // rekey when we're halfway there.
        let max = Seq::max::<<CS::Aead as Aead>::NonceSize>();
        let seq = ctx.seal.seq().to_u64();
        seq >= max / 2
    }

    /// Generates a new HPKE encryption context and returns the
    /// resulting peer encapsulation.
    fn rekey(&mut self) -> Result<Encap<CS>, HpkeError> {
        let (ctx, enc) = Ctx::client(&mut self.rng, &self.pk, &self.info)?;
        self.ctx = Some(ctx);
        // Rekeying takes so long (relatively speaking, anyway)
        // that this should never overflow.
        self.rekeys += 1;
        Ok(enc)
    }
}

impl<S, R, CS, Item, SinkItem> Stream for ClientConn<S, R, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Csprng,
    CS: CipherSuite,
    Item: DeserializeOwned,
{
    type Item = io::Result<Item>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ctx.is_none() {
            // In tarpc the client always writes first. We create
            // our encryption context the first time we write, so
            // if we get here we haven't written yet.
            // TODO(eric): should we return an error instead?
            return Poll::Pending;
        }
        let Some(msg) = ready!(self.as_mut().project().inner.poll_next(cx)?) else {
            return Poll::Ready(None);
        };
        match msg {
            ServerMsg::Data(data) => {
                let pt = self.decrypt(data)?;
                Poll::Ready(Some(Ok(pt)))
            }
        }
    }
}

impl<S, R, CS, Item, SinkItem> Sink<SinkItem> for ClientConn<S, R, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Csprng,
    CS: CipherSuite,
    SinkItem: Serialize,
{
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().project().inner.poll_ready(cx)?);

        // Do we need to rekey?
        if let Some(msg) = self.try_rekey().map_err(other)? {
            // We updated our keys, so forward the message on to
            // the server.
            self.as_mut().project().inner.start_send(msg)?;

            // Each call to `start_send` must be preceeded by
            // a call to `poll_ready`, so call `poll_ready`
            // again.
            ready!(self.as_mut().project().inner.poll_ready(cx)?);
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        let data = self.encrypt(item)?;
        self.project().inner.start_send(ClientMsg::Data(data))?;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

impl<S, R, CS, Item, SinkItem> fmt::Debug for ClientConn<S, R, CS, Item, SinkItem>
where
    CS: CipherSuite,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("pk", &self.pk)
            .field("info", &self.info)
            .field("ctx", &self.ctx)
            .field("rekeys", &self.rekeys)
            .finish_non_exhaustive()
    }
}

/// A message (request) sent by the client to the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
enum ClientMsg {
    Data(Data),
    Rekey(Rekey),
}

/// Some encrypted data.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Data {
    /// The position of this ciphertext in the stream of
    /// messages.
    seq: u64,
    /// The ciphertext.
    ciphertext: BytesMut,
    /// The authentication tag.
    tag: Bytes,
}

/// Instructs the server to rekey.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Rekey {
    /// The HPKE peer encapsulation.
    enc: Bytes,
}

/// Creates a server-side transport.
pub fn server<L, CS, Item, SinkItem>(
    listener: L,
    codec: LengthDelimitedCodec,
    sk: ApiKey<CS>,
    info: &[u8],
) -> Server<L, CS, Item, SinkItem>
where
    CS: CipherSuite,
{
    Server {
        listener,
        codec,
        sk: Arc::new(sk),
        info: Arc::from(info),
        _marker: PhantomData,
    }
}

/// Creates [`ServerConn`]s.
///
/// It is created by [`server`]
#[derive(Debug)]
#[pin_project]
pub struct Server<L, CS, Item, SinkItem>
where
    CS: CipherSuite,
{
    #[pin]
    listener: L,
    codec: LengthDelimitedCodec,
    /// The server's secret key.
    sk: Arc<ApiKey<CS>>,
    /// The "info" parameter when rekeying.
    info: Arc<[u8]>,
    _marker: PhantomData<fn() -> (Item, SinkItem)>,
}

impl<S, L, CS, Item, SinkItem> Stream for Server<L, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    L: TryStream<Ok = S, Error = io::Error>,
    CS: CipherSuite,
{
    type Item = io::Result<ServerConn<S, CS, Item, SinkItem>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Some(io) = ready!(self.as_mut().project().listener.try_poll_next(cx)?) else {
            return Poll::Ready(None);
        };
        let conn = ServerConn {
            inner: serde_transport::new(
                Framed::new(io, self.codec.clone()),
                MessagePack::default(),
            ),
            sk: Arc::clone(&self.sk),
            info: Arc::clone(&self.info),
            ctx: None,
            _marker: PhantomData,
        };
        Poll::Ready(Some(Ok(conn)))
    }
}

/// An encrypted [`Transport`][tarpc::Transport] for the server.
///
/// It is created by reading from [`Server`], which is
/// a [`Stream`].
#[pin_project]
pub struct ServerConn<S, CS, Item, SinkItem>
where
    CS: CipherSuite,
{
    /// The underlying transport.
    #[pin]
    inner: Transport<S, ClientMsg, ServerMsg, MessagePack<ClientMsg, ServerMsg>>,
    /// The server's secret key.
    sk: Arc<ApiKey<CS>>,
    /// The "info" parameter when rekeying.
    info: Arc<[u8]>,
    /// The HPKE encryption context.
    ///
    /// This is set to `Some` after the client sends the first
    /// `Rekey` message.
    ///
    /// It is periodically updated via rekeying in order to keep
    /// the keys fresh.
    ctx: Option<Ctx<CS>>,
    _marker: PhantomData<fn() -> (Item, SinkItem)>,
}

impl<S, CS, Item, SinkItem> ServerConn<S, CS, Item, SinkItem>
where
    CS: CipherSuite,
    SinkItem: Serialize,
{
    /// Serializes `item`, encrypts and authenticates the
    /// resulting bytes, and returns the ciphertext.
    ///
    /// It is an error if `self.ctx` has not yet been
    /// initialized.
    fn encrypt(&mut self, item: SinkItem) -> io::Result<Data> {
        self.ctx
            .as_mut()
            .assume("`self.ctx` should be `Some`")
            .map_err(other)?
            .encrypt::<Item, SinkItem>(item, Side::Server)
            .map_err(other)
    }
}

impl<S, CS, Item, SinkItem> ServerConn<S, CS, Item, SinkItem>
where
    CS: CipherSuite,
    Item: DeserializeOwned,
{
    /// Decrypts and authenticates `data`, then deserializes the
    /// resulting plaintext and returns the resulting `Item`.
    ///
    /// It is an error if `self.ctx` has not yet been
    /// initialized.
    fn decrypt(&mut self, data: Data) -> io::Result<Item> {
        self.ctx
            .as_mut()
            .assume("`self.ctx` should be `Some`")
            .map_err(other)?
            .decrypt::<Item, SinkItem>(data, Side::Client)
            .map_err(other)
    }
}

impl<S, CS, Item, SinkItem> ServerConn<S, CS, Item, SinkItem>
where
    CS: CipherSuite,
{
    /// Updates the HPKE encryption context per the peer's
    /// encapsulation.
    fn rekey(&mut self, msg: Rekey) -> Result<(), HpkeError> {
        let ctx = Ctx::server(&self.sk, &self.info, &msg.enc)?;
        self.ctx = Some(ctx);
        Ok(())
    }
}

impl<S, CS, Item, SinkItem> Stream for ServerConn<S, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite + Unpin,
    CS: CipherSuite,
    Item: DeserializeOwned,
{
    type Item = io::Result<Item>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Skip past control (i.e., non-`Data`) messages.
        loop {
            let Some(msg) = ready!(self.as_mut().project().inner.poll_next(cx)?) else {
                return Poll::Ready(None);
            };
            match msg {
                ClientMsg::Data(data) => {
                    let pt = self.decrypt(data)?;
                    return Poll::Ready(Some(Ok(pt)));
                }
                ClientMsg::Rekey(rekey) => self.rekey(rekey).map_err(other)?,
            }
        }
    }
}

impl<S, CS, Item, SinkItem> Sink<SinkItem> for ServerConn<S, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite + Unpin,
    CS: CipherSuite,
    SinkItem: Serialize,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        let data = self.encrypt(item)?;
        self.project().inner.start_send(ServerMsg::Data(data))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

impl<S, CS, Item, SinkItem> fmt::Debug for ServerConn<S, CS, Item, SinkItem>
where
    CS: CipherSuite,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("sk", &self.sk)
            .field("info", &self.info)
            .field("ctx", &self.ctx)
            .finish_non_exhaustive()
    }
}

/// A message (response) sent by the server to the client.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
enum ServerMsg {
    Data(Data),
}

/// Unix utilities.
#[cfg(unix)]
#[cfg_attr(docsrs, doc(cfg(unix)))]
pub mod unix {
    use core::{
        pin::Pin,
        task::{Context, Poll},
    };

    use futures_util::{ready, Stream};
    use tokio::{
        io,
        net::{UnixListener, UnixStream},
    };

    /// Converts a [`UnixListener`] into a [`Stream`].
    #[derive(Debug)]
    pub struct UnixListenerStream(UnixListener);

    impl Stream for UnixListenerStream {
        type Item = io::Result<UnixStream>;

        fn poll_next(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<io::Result<UnixStream>>> {
            let (stream, _) = ready!(self.0.poll_accept(cx))?;
            Poll::Ready(Some(Ok(stream)))
        }
    }

    impl From<UnixListener> for UnixListenerStream {
        #[inline]
        fn from(listener: UnixListener) -> Self {
            Self(listener)
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
#[allow(clippy::panic)]
mod tests {
    use std::panic;

    use aranya_crypto::{
        default::{DefaultCipherSuite, DefaultEngine},
        Rng,
    };
    use backon::{ExponentialBuilder, Retryable as _};
    use futures_util::{SinkExt, TryStreamExt};
    use tokio::{
        net::{UnixListener, UnixStream},
        task::JoinSet,
    };

    use super::*;

    impl<S, R, CS, Item, SinkItem> ClientConn<S, R, CS, Item, SinkItem>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        CS: CipherSuite,
    {
        fn force_rekey(&mut self) {
            self.ctx = None;
        }
    }

    type CS = DefaultCipherSuite;

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct Ping {
        v: usize,
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct Pong {
        v: usize,
    }

    /// Basic one client, one server ping pong test.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ping_pong() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().to_path_buf().join("sock"));
        let info = Arc::from(path.as_os_str().as_encoded_bytes());

        let (mut eng, _) = DefaultEngine::from_entropy(Rng);
        let sk = ApiKey::<CS>::new(&mut eng);
        let pk = sk.public().unwrap();

        const MAX_PING_PONGS: usize = 100;

        let mut set = JoinSet::new();

        {
            let path = Arc::clone(&path);
            let info = Arc::clone(&info);
            set.spawn(async move {
                let listener = UnixListener::bind(&*path)?;
                let codec = LengthDelimitedCodec::builder()
                    .max_frame_length(usize::MAX)
                    .new_codec();
                let mut server = server::<_, _, Ping, Pong>(
                    unix::UnixListenerStream::from(listener),
                    codec.clone(),
                    sk,
                    &info,
                );

                let mut conn = server.try_next().await.unwrap().unwrap();
                for v in 0..MAX_PING_PONGS {
                    let got = conn.try_next().await?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "stream finished early")
                    })?;
                    assert_eq!(got, Ping { v });
                    conn.send(Pong {
                        v: got.v.wrapping_add(1),
                    })
                    .await?;
                }
                io::Result::Ok(())
            });
        }

        {
            let path = Arc::clone(&path);
            let info = Arc::clone(&info);
            set.spawn(async move {
                let codec = LengthDelimitedCodec::builder()
                    .max_frame_length(usize::MAX)
                    .new_codec();
                let sock = (|| UnixStream::connect(&*path))
                    .retry(ExponentialBuilder::default())
                    .await
                    .unwrap();
                let mut client = client::<_, _, _, Pong, Ping>(sock, codec, Rng, pk, &info);
                for v in 0..MAX_PING_PONGS {
                    client.send(Ping { v }).await?;
                    let got = client.try_next().await?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "stream finished early")
                    })?;
                    let want = Pong {
                        v: v.wrapping_add(1),
                    };
                    assert_eq!(got, want)
                }
                Ok(())
            });
        }

        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    set.abort_all();
                    panic!("{err}");
                }
                Err(err) if err.is_panic() => panic::resume_unwind(err.into_panic()),
                Err(err) => panic!("{err}"),
            }
        }
    }

    /// One client rekeys each request.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_rekey() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().to_path_buf().join("sock"));
        let info = Arc::from(path.as_os_str().as_encoded_bytes());

        let (mut eng, _) = DefaultEngine::from_entropy(Rng);
        let sk = ApiKey::<CS>::new(&mut eng);
        let pk = sk.public().unwrap();

        const MAX_PING_PONGS: usize = 100;

        let mut set = JoinSet::new();

        {
            let path = Arc::clone(&path);
            let info = Arc::clone(&info);
            set.spawn(async move {
                let listener = UnixListener::bind(&*path).unwrap();
                let codec = LengthDelimitedCodec::builder()
                    .max_frame_length(usize::MAX)
                    .new_codec();
                let mut server = server::<_, _, Ping, Pong>(
                    unix::UnixListenerStream::from(listener),
                    codec.clone(),
                    sk,
                    &info,
                );
                let mut conn = server.try_next().await.unwrap().unwrap();
                for v in 0..MAX_PING_PONGS {
                    let got = conn.try_next().await?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "stream finished early")
                    })?;
                    // In this test the client rekeys each time
                    // it sends data, so our seq number should
                    // always be zero.
                    let ctx = conn.ctx.as_ref().map(|ctx| &ctx.seal).unwrap();
                    assert_eq!(ctx.seq(), Seq::ZERO);

                    assert_eq!(got, Ping { v });
                    conn.send(Pong {
                        v: got.v.wrapping_add(1),
                    })
                    .await?;

                    // Double check that it actually increments.
                    let ctx = conn.ctx.as_ref().map(|ctx| &ctx.seal).unwrap();
                    assert_eq!(ctx.seq(), Seq::new(1));
                }
                io::Result::Ok(())
            });
        }

        {
            let path = Arc::clone(&path);
            let info = Arc::clone(&info);
            set.spawn(async move {
                let codec = LengthDelimitedCodec::builder()
                    .max_frame_length(usize::MAX)
                    .new_codec();
                let sock = (|| UnixStream::connect(&*path))
                    .retry(ExponentialBuilder::default())
                    .await
                    .unwrap();
                let mut client = client::<_, _, _, Pong, Ping>(sock, codec, Rng, pk, &info);
                for v in 0..MAX_PING_PONGS {
                    let last = client.rekeys;
                    client.force_rekey();
                    client.send(Ping { v }).await.unwrap();
                    assert_eq!(client.rekeys, last + 1);
                    let got = client.try_next().await?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "stream finished early")
                    })?;
                    let want = Pong {
                        v: v.wrapping_add(1),
                    };
                    assert_eq!(got, want)
                }
                Ok(())
            });
        }

        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    set.abort_all();
                    panic!("{err}");
                }
                Err(err) if err.is_panic() => panic::resume_unwind(err.into_panic()),
                Err(err) => panic!("{err}"),
            }
        }
    }

    /// N clients make repeated requests to one server.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_multi_client() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().to_path_buf().join("sock"));
        let info = Arc::from(path.as_os_str().as_encoded_bytes());

        let (mut eng, _) = DefaultEngine::from_entropy(Rng);
        let sk = ApiKey::<CS>::new(&mut eng);
        let pk = sk.public().unwrap();

        const MAX_PING_PONGS: usize = 2;
        const MAX_CLIENTS: usize = 10;

        let mut set = JoinSet::new();

        {
            let path = Arc::clone(&path);
            let info = Arc::clone(&info);
            set.spawn(async move {
                let listener = UnixListener::bind(&*path).unwrap();
                let codec = LengthDelimitedCodec::builder()
                    .max_frame_length(usize::MAX)
                    .new_codec();
                let mut server = server::<_, _, Ping, Pong>(
                    unix::UnixListenerStream::from(listener),
                    codec.clone(),
                    sk,
                    &info,
                );
                let mut set = JoinSet::new();
                for _ in 0..MAX_CLIENTS {
                    let mut conn = server.try_next().await?.unwrap();
                    set.spawn(async move {
                        for v in 0..MAX_PING_PONGS {
                            let got = conn.try_next().await?.ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "client stream finished early",
                                )
                            })?;
                            assert_eq!(got, Ping { v });
                            conn.send(Pong {
                                v: got.v.wrapping_add(1),
                            })
                            .await?;
                        }
                        io::Result::Ok(())
                    });
                }
                set.join_all()
                    .await
                    .into_iter()
                    .find(|v| v.is_err())
                    .unwrap_or(Ok(()))
            });
        }

        for _ in 0..10 {
            let path = Arc::clone(&path);
            let info = Arc::clone(&info);
            let pk = pk.clone();
            set.spawn(async move {
                let codec = LengthDelimitedCodec::builder()
                    .max_frame_length(usize::MAX)
                    .new_codec();
                let sock = (|| UnixStream::connect(&*path))
                    .retry(ExponentialBuilder::default())
                    .await
                    .unwrap();
                let mut client = client::<_, _, _, Pong, Ping>(sock, codec, Rng, pk, &info);
                for v in 0..MAX_PING_PONGS {
                    client.send(Ping { v }).await?;
                    let got = client.try_next().await?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "server stream finished early")
                    })?;
                    let want = Pong {
                        v: v.wrapping_add(1),
                    };
                    assert_eq!(got, want);
                }
                Ok(())
            });
        }

        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    set.abort_all();
                    panic!("{err}");
                }
                Err(err) if err.is_panic() => panic::resume_unwind(err.into_panic()),
                Err(err) => panic!("{err}"),
            }
        }
    }
}
