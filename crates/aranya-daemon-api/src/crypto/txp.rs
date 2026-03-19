//! Encrypted RPC transport wrapper.

use core::{borrow::Borrow, error, fmt};
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
use futures_util::{SinkExt as _, Stream, StreamExt as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

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
        rng: R,
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
    fn encrypt<T: Serialize>(&mut self, item: &T, side: Side) -> io::Result<Data> {
        let serialized = postcard::to_allocvec(item).map_err(other)?;
        let mut plaintext = BytesMut::from(serialized.as_slice());
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
    fn decrypt<T: DeserializeOwned>(&mut self, data: Data, side: Side) -> io::Result<T> {
        let Data {
            seq,
            mut ciphertext,
            tag,
        } = data;
        let ad = auth_data(Seq::new(seq), side);
        self.open
            .open_in_place_at(&mut ciphertext, &tag, &ad, Seq::new(seq))
            .map_err(other)?;
        let item = postcard::from_bytes(&ciphertext).map_err(other)?;
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

/// A message (request) sent by the client to the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
enum ClientMsg {
    Data(Data),
    Rekey(Rekey),
}

/// A message (response) sent by the server to the client.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
enum ServerMsg {
    Data(Data),
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

/// Serialize a message and send it as a length-delimited frame.
async fn frame_send<S, T>(framed: &mut Framed<S, LengthDelimitedCodec>, msg: T) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = postcard::to_allocvec(&msg).map_err(other)?;
    framed.send(Bytes::from(bytes)).await
}

/// Receive a length-delimited frame and deserialize it.
async fn frame_recv<S, T>(framed: &mut Framed<S, LengthDelimitedCodec>) -> io::Result<Option<T>>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: DeserializeOwned,
{
    let Some(frame) = framed.next().await else {
        return Ok(None);
    };
    let msg = postcard::from_bytes(&frame?).map_err(other)?;
    Ok(Some(msg))
}

/// Creates a client-side transport.
pub fn client<S, R, CS>(
    io: S,
    codec: LengthDelimitedCodec,
    rng: R,
    pk: PublicApiKey<CS>,
    info: &[u8],
) -> ClientConn<S, R, CS>
where
    S: AsyncRead + AsyncWrite,
    CS: CipherSuite,
{
    ClientConn {
        inner: Framed::new(io, codec),
        rng,
        pk,
        info: Box::from(info),
        ctx: None,
        rekeys: 0,
    }
}

/// An encrypted connection for the client.
///
/// It is created by [`client`].
pub struct ClientConn<S, R, CS>
where
    CS: CipherSuite,
{
    /// The underlying length-delimited transport.
    inner: Framed<S, LengthDelimitedCodec>,
    /// For rekeying.
    rng: R,
    /// The server's public key.
    pk: PublicApiKey<CS>,
    /// The "info" parameter when rekeying.
    info: Box<[u8]>,
    /// HPKE encryption context. Set on first send, updated on rekey.
    ctx: Option<Ctx<CS>>,
    /// The number of times we've rekeyed, including the initial keying.
    ///
    /// Mostly for debugging purposes.
    rekeys: usize,
}

impl<S, R, CS> ClientConn<S, R, CS>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Csprng,
    CS: CipherSuite,
{
    /// Send a message to the server.
    ///
    /// Handles rekeying automatically before sending.
    pub async fn send<T: Serialize>(&mut self, item: T) -> io::Result<()> {
        if self.need_rekey() {
            let enc = self.rekey().map_err(other)?;
            let rekey_msg = ClientMsg::Rekey(Rekey {
                enc: Bytes::from(enc.borrow().to_vec()),
            });
            frame_send(&mut self.inner, &rekey_msg).await?;
        }

        let data = self
            .ctx
            .as_mut()
            .assume("`self.ctx` should be `Some`")
            .map_err(other)?
            .encrypt(&item, Side::Client)?;

        frame_send(&mut self.inner, &ClientMsg::Data(data)).await
    }

    /// Receive a message from the server.
    ///
    /// Returns `Ok(None)` if the connection was closed.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
        let Some(ServerMsg::Data(data)) = frame_recv(&mut self.inner).await? else {
            return Ok(None);
        };
        let item = self
            .ctx
            .as_mut()
            .assume("`self.ctx` should be `Some`")
            .map_err(other)?
            .decrypt(data, Side::Server)?;
        Ok(Some(item))
    }

    /// Reports whether we need to generate a new HPKE encryption context.
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

impl<S, R, CS: CipherSuite> fmt::Debug for ClientConn<S, R, CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConn")
            .field("pk", &self.pk)
            .field("info", &self.info)
            .field("ctx", &self.ctx)
            .field("rekeys", &self.rekeys)
            .finish_non_exhaustive()
    }
}

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

/// Accepts incoming connections and wraps them in [`ServerConn`]s.
///
/// It is created by [`server`]
#[derive(Debug)]
pub struct Server<L, CS: CipherSuite> {
    listener: L,
    codec: LengthDelimitedCodec,
    /// The server's secret key.
    sk: Arc<ApiKey<CS>>,
    /// The "info" parameter when rekeying.
    info: Arc<[u8]>,
}

impl<S, L, CS> Server<L, CS>
where
    S: AsyncRead + AsyncWrite,
    L: Stream<Item = io::Result<S>> + Unpin,
    CS: CipherSuite,
{
    /// Accept the next incoming connection.
    ///
    /// Returns `None` when the listener is exhausted.
    pub async fn accept(&mut self) -> Option<io::Result<ServerConn<S, CS>>> {
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

/// An encrypted transport for the server.
///
/// It is created by reading from [`Server`], which is
/// a [`Stream`].
pub struct ServerConn<S, CS: CipherSuite> {
    /// The underlying length-delimited transport.
    inner: Framed<S, LengthDelimitedCodec>,
    /// The server's secret key.
    sk: Arc<ApiKey<CS>>,
    /// The "info" parameter when rekeying.
    info: Arc<[u8]>,
    /// The HPKE encryption context.
    ///
    /// This is set to `Some` after the client sends the first `Rekey` message.
    ///
    /// It is periodically updated via rekeying in order to keep the keys fresh.
    ctx: Option<Ctx<CS>>,
}

impl<S, CS> ServerConn<S, CS>
where
    S: AsyncRead + AsyncWrite + Unpin,
    CS: CipherSuite,
{
    /// Send a message to the client.
    pub async fn send<T: Serialize>(&mut self, item: T) -> io::Result<()> {
        let data = self
            .ctx
            .as_mut()
            .assume("`self.ctx` should be `Some`")
            .map_err(other)?
            .encrypt(&item, Side::Server)?;

        frame_send(&mut self.inner, &ServerMsg::Data(data)).await
    }

    /// Receive a message from the client.
    ///
    /// Handles rekey messages automatically.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
        // Loop to skip past control messages (rekeying)
        loop {
            let Some(msg) = frame_recv(&mut self.inner).await? else {
                return Ok(None);
            };
            match msg {
                ClientMsg::Data(data) => {
                    let item = self
                        .ctx
                        .as_mut()
                        .assume("`self.ctx` should be `Some`")
                        .map_err(other)?
                        .decrypt(data, Side::Client)?;
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

impl<S, CS: CipherSuite> fmt::Debug for ServerConn<S, CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConn")
            .field("sk", &self.sk)
            .field("info", &self.info)
            .field("ctx", &self.ctx)
            .finish_non_exhaustive()
    }
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
    use tokio::{
        net::{UnixListener, UnixStream},
        task::JoinSet,
    };

    use super::*;

    impl<S, R, CS> ClientConn<S, R, CS>
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

        let (eng, _) = DefaultEngine::from_entropy(Rng);
        let sk = ApiKey::<CS>::new(&eng);
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
                let mut server = server(unix::UnixListenerStream::from(listener), codec, sk, &info);

                let mut conn = server.accept().await.unwrap()?;
                for v in 0..MAX_PING_PONGS {
                    let got: Ping = conn.recv().await?.ok_or_else(|| {
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
                let mut client = client(sock, codec, Rng, pk, &info);
                for v in 0..MAX_PING_PONGS {
                    client.send(Ping { v }).await?;
                    let got: Pong = client.recv().await?.ok_or_else(|| {
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

        let (eng, _) = DefaultEngine::from_entropy(Rng);
        let sk = ApiKey::<CS>::new(&eng);
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
                let mut server = server(
                    unix::UnixListenerStream::from(listener),
                    codec.clone(),
                    sk,
                    &info,
                );
                let mut conn = server.accept().await.unwrap().unwrap();
                for v in 0..MAX_PING_PONGS {
                    let got: Ping = conn.recv().await?.ok_or_else(|| {
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
                let mut client = client(sock, codec, Rng, pk, &info);
                for v in 0..MAX_PING_PONGS {
                    let last = client.rekeys;
                    client.force_rekey();
                    client.send(Ping { v }).await.unwrap();
                    assert_eq!(client.rekeys, last + 1);
                    let got: Pong = client.recv().await?.ok_or_else(|| {
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

        let (eng, _) = DefaultEngine::from_entropy(Rng);
        let sk = ApiKey::<CS>::new(&eng);
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
                let mut server = server(
                    unix::UnixListenerStream::from(listener),
                    codec.clone(),
                    sk,
                    &info,
                );
                let mut set = JoinSet::new();
                for _ in 0..MAX_CLIENTS {
                    let mut conn = server.accept().await.unwrap()?;
                    set.spawn(async move {
                        for v in 0..MAX_PING_PONGS {
                            let got: Ping = conn.recv().await?.ok_or_else(|| {
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
                let mut client = client(sock, codec, Rng, pk, &info);
                for v in 0..MAX_PING_PONGS {
                    client.send(Ping { v }).await?;
                    let got: Pong = client.recv().await?.ok_or_else(|| {
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
