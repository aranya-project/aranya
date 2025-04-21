//! Encrypted tarpc [`Transport`]s.
//!
//! [`Transport`][tarpc::Transport]

use core::{
    borrow::Borrow,
    error,
    marker::PhantomData,
    pin::{pin, Pin},
    task::{Context, Poll},
};
use std::sync::Arc;

use aranya_crypto::{
    aead::Tag,
    csprng::Csprng,
    hpke::{Hpke, HpkeError, Mode, OpenCtx, SealCtx, Seq},
    import::Import,
    kem::Kem,
    CipherSuite,
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
    io::Error::new(io::ErrorKind::Other, err)
}

const SERVER_KEY_CTX: &[u8] = b"aranya daemon api server seal key";
const SERVER_NONCE_CTX: &[u8] = b"aranya daemon api server seal nonce";

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
    R: Csprng,
    CS: CipherSuite,
    Item: for<'de> Deserialize<'de>,
    SinkItem: Serialize,
{
    ClientConn {
        inner: serde_transport::new(Framed::new(io, codec), MessagePack::default()),
        rng,
        pk,
        info: info.to_vec(),
        seal: None,
        open: None,
        _marker: PhantomData,
    }
}

/// An encrypted [`Transport`][tarpc::Transport].
#[pin_project]
pub struct ClientConn<S, R, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    CS: CipherSuite,
{
    #[pin]
    inner: Transport<S, ServerMsg, ClientMsg, MessagePack<ServerMsg, ClientMsg>>,
    rng: R,
    pk: PublicApiKey<CS>,
    info: Vec<u8>,
    seal: Option<SealCtx<CS::Aead>>,
    open: Option<OpenCtx<CS::Aead>>,
    #[allow(clippy::type_complexity)]
    _marker: PhantomData<fn() -> (Item, SinkItem)>,
}

impl<S, R, CS, Item, SinkItem> ClientConn<S, R, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    CS: CipherSuite,
    SinkItem: Serialize,
{
    fn encrypt(&mut self, item: SinkItem) -> io::Result<Data> {
        let mut codec = MessagePack::<Item, SinkItem>::default();
        let mut plaintext = BytesMut::from(pin!(codec).serialize(&item)?);
        let mut tag = BytesMut::from(&*Tag::<CS::Aead>::default());
        self.seal
            .as_mut()
            .assume("`self.seal` should be `Some`")
            .map_err(other)?
            .seal_in_place(&mut plaintext, &mut tag, &[])
            .map_err(other)?;
        Ok(Data {
            ciphertext: plaintext,
            tag: tag.freeze(),
        })
    }
}

impl<S, R, CS, Item, SinkItem> ClientConn<S, R, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    CS: CipherSuite,
    Item: DeserializeOwned,
{
    fn decrypt(&mut self, data: Data) -> io::Result<Item> {
        let Data {
            mut ciphertext,
            tag,
        } = data;
        self.open
            .as_mut()
            .assume("`self.open` should be `Some`")
            .map_err(other)?
            .open_in_place(&mut ciphertext, &tag, &[])
            .map_err(other)?;
        let mut codec = MessagePack::<Item, SinkItem>::default();
        let item = pin!(codec).deserialize(&ciphertext)?;
        Ok(item)
    }
}

impl<S, R, CS, Item, SinkItem> ClientConn<S, R, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    R: Csprng,
    CS: CipherSuite,
{
    fn rekey(&mut self) -> Result<Hello, HpkeError> {
        let (enc, send) = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send(
            &mut self.rng,
            Mode::Base,
            self.pk.as_inner(),
            &self.info,
        )?;
        let (open_key, open_nonce) = {
            let key = send.export(SERVER_KEY_CTX)?;
            let nonce = send.export(SERVER_NONCE_CTX)?;
            (key, nonce)
        };
        let (seal_key, seal_nonce) = send
            .into_raw_parts()
            .assume("should be able to decompose `SendCtx`")?;
        self.seal = Some(SealCtx::new(&seal_key, &seal_nonce, Seq::ZERO)?);
        self.open = Some(OpenCtx::new(&open_key, &open_nonce, Seq::ZERO)?);

        Ok(Hello {
            enc: Bytes::from(enc.borrow().to_vec()),
        })
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
        if self.seal.is_none() {
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

impl<S, R, CS, Item, SinkItem> ClientConn<S, R, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Csprng,
    CS: CipherSuite,
    SinkItem: Serialize,
{
    fn maybe_rekey(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.seal.is_some() {
            return Ok(());
        }
        let hello = self.rekey().map_err(other)?;
        self.as_mut()
            .project()
            .inner
            .start_send(ClientMsg::Hello(hello))?;
        // Each call to `start_send` must be preceeded by
        // a call to `poll_ready`, so we have to call
        // `poll_ready` again.
        ready!(self.as_mut().project().inner.poll_ready(cx)?);
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
        self.maybe_rekey(cx)?;
        ready!(self.as_mut().project().inner.poll_ready(cx)?);
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
enum ClientMsg {
    Hello(Hello),
    Data(Data),
    Rekey(Rekey),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Hello {
    enc: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Data {
    ciphertext: BytesMut,
    tag: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Rekey {
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
#[pin_project]
pub struct Server<L, CS, Item, SinkItem>
where
    CS: CipherSuite,
{
    #[pin]
    listener: L,
    codec: LengthDelimitedCodec,
    sk: Arc<ApiKey<CS>>,
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
            seal: None,
            open: None,
            _marker: PhantomData,
        };
        Poll::Ready(Some(Ok(conn)))
    }
}

/// An encrypted [`Transport`][tarpc::Transport].
#[pin_project]
pub struct ServerConn<S, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    CS: CipherSuite,
{
    #[pin]
    inner: Transport<S, ClientMsg, ServerMsg, MessagePack<ClientMsg, ServerMsg>>,
    sk: Arc<ApiKey<CS>>,
    info: Arc<[u8]>,
    seal: Option<SealCtx<CS::Aead>>,
    open: Option<OpenCtx<CS::Aead>>,
    #[allow(clippy::type_complexity)]
    _marker: PhantomData<fn() -> (Item, SinkItem)>,
}

impl<S, CS, Item, SinkItem> ServerConn<S, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    CS: CipherSuite,
    SinkItem: Serialize,
{
    fn encrypt(&mut self, item: SinkItem) -> io::Result<Data> {
        let mut codec = MessagePack::<Item, SinkItem>::default();
        let mut plaintext = BytesMut::from(pin!(codec).serialize(&item)?);
        let mut tag = BytesMut::from(&*Tag::<CS::Aead>::default());
        self.seal
            .as_mut()
            .assume("`self.seal` should be `Some`")
            .map_err(other)?
            .seal_in_place(&mut plaintext, &mut tag, &[])
            .map_err(other)?;
        Ok(Data {
            ciphertext: plaintext,
            tag: tag.freeze(),
        })
    }
}

impl<S, CS, Item, SinkItem> ServerConn<S, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    CS: CipherSuite,
    Item: DeserializeOwned,
{
    fn decrypt(&mut self, data: Data) -> io::Result<Item> {
        let Data {
            mut ciphertext,
            tag,
        } = data;
        self.open
            .as_mut()
            .assume("`self.open` should be `Some`")
            .map_err(other)?
            .open_in_place(&mut ciphertext, &tag, &[])
            .map_err(other)?;
        let mut codec = MessagePack::<Item, SinkItem>::default();
        let item = pin!(codec).deserialize(&ciphertext)?;
        Ok(item)
    }
}

impl<S, CS, Item, SinkItem> ServerConn<S, CS, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    CS: CipherSuite,
{
    fn rekey(&mut self, enc: &[u8]) -> Result<(), HpkeError> {
        let enc = <<CS::Kem as Kem>::Encap as Import<_>>::import(enc)?;

        let recv = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_recv(
            Mode::Base,
            &enc,
            self.sk.as_inner(),
            &self.info,
        )?;
        let (seal_key, seal_nonce) = {
            let key = recv.export(SERVER_KEY_CTX)?;
            let nonce = recv.export(SERVER_NONCE_CTX)?;
            (key, nonce)
        };
        let (open_key, open_nonce) = recv
            .into_raw_parts()
            .assume("should be able to decompose `SendCtx`")?;
        self.seal = Some(SealCtx::new(&seal_key, &seal_nonce, Seq::ZERO)?);
        self.open = Some(OpenCtx::new(&open_key, &open_nonce, Seq::ZERO)?);
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
        loop {
            let Some(msg) = ready!(self.as_mut().project().inner.poll_next(cx)?) else {
                return Poll::Ready(None);
            };
            match msg {
                ClientMsg::Hello(hello) => self.rekey(&hello.enc).map_err(other)?,
                ClientMsg::Data(data) => {
                    let pt = self.decrypt(data)?;
                    return Poll::Ready(Some(Ok(pt)));
                }
                ClientMsg::Rekey(rekey) => self.rekey(&rekey.enc).map_err(other)?,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
enum ServerMsg {
    Data(Data),
}

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
            self.seal = None;
            self.open = None;
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ping_pong() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().to_path_buf().join("sock"));
        let info = Arc::from(path.as_os_str().as_encoded_bytes());

        let (mut eng, _) = DefaultEngine::from_entropy(Rng);
        let sk = ApiKey::<CS>::new(&mut eng);
        let pk = sk.public().unwrap();

        const N: usize = 100;

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
                    &*info,
                );
                let mut want = Ping { v: 0 };
                let mut n = 0;
                while let Some(mut conn) = server.try_next().await? {
                    while let Some(got) = conn.try_next().await? {
                        assert_eq!(got, want);
                        let pong = Pong {
                            v: got.v.wrapping_add(1),
                        };
                        conn.send(pong).await?;
                        want = Ping { v: pong.v };
                        n += 1;
                        if n >= N {
                            return Ok(());
                        }
                    }
                }
                Ok::<_, io::Error>(())
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
                let mut client = client::<_, _, _, Pong, Ping>(sock, codec, Rng, pk, &*info);
                for v in 0..N {
                    client.send(Ping { v }).await.unwrap();
                    let got = client.try_next().await.unwrap().unwrap();
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_rekey() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().to_path_buf().join("sock"));
        let info = Arc::from(path.as_os_str().as_encoded_bytes());

        let (mut eng, _) = DefaultEngine::from_entropy(Rng);
        let sk = ApiKey::<CS>::new(&mut eng);
        let pk = sk.public().unwrap();

        const N: usize = 100;

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
                    &*info,
                );
                let mut want = Ping { v: 0 };
                let mut n = 0;
                while let Some(mut conn) = server.try_next().await? {
                    while let Some(got) = conn.try_next().await? {
                        assert_eq!(got, want);
                        let pong = Pong {
                            v: got.v.wrapping_add(1),
                        };
                        conn.send(pong).await?;
                        want = Ping { v: pong.v };
                        n += 1;
                        if n >= N {
                            return Ok(());
                        }
                    }
                }
                Ok::<_, io::Error>(())
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
                let mut client = client::<_, _, _, Pong, Ping>(sock, codec, Rng, pk, &*info);
                for v in 0..N {
                    client.force_rekey();
                    client.send(Ping { v }).await.unwrap();
                    let got = client.try_next().await.unwrap().unwrap();
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
}
