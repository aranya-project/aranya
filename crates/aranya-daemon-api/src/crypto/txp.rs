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
    let inner = serde_transport::new(Framed::new(io, codec.clone()), MessagePack::default());
    ClientConn {
        inner,
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
            let key = send.export(b"api server seal key")?;
            let nonce = send.export(b"api server seal nonce")?;
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
        let msg = ready!(self.as_mut().project().inner.poll_next(cx)?);
        let Some(msg) = msg else {
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

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        if self.seal.is_none() {
            let hello = self.rekey().map_err(other)?;
            self.as_mut()
                .project()
                .inner
                .start_send(ClientMsg::Hello(hello))?;
        }
        let data = self.encrypt(item)?;
        self.project().inner.start_send(ClientMsg::Data(data))
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
        let inner =
            serde_transport::new(Framed::new(io, self.codec.clone()), MessagePack::default());
        let conn = ServerConn {
            inner,
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
            let key = recv.export(b"cryptio server seal key")?;
            let nonce = recv.export(b"cryptio server seal nonce")?;
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
        let msg = ready!(self.as_mut().project().inner.poll_next(cx)?);
        let Some(msg) = msg else {
            return Poll::Ready(None);
        };
        match msg {
            ClientMsg::Hello(hello) => {
                self.rekey(&hello.enc).map_err(other)?;
                Poll::Pending
            }
            ClientMsg::Data(data) => {
                let pt = self.decrypt(data)?;
                Poll::Ready(Some(Ok(pt)))
            }
            ClientMsg::Rekey(rekey) => {
                self.rekey(&rekey.enc).map_err(other)?;
                Poll::Pending
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

#[cfg(test)]
mod tests {
    use aranya_crypto::{
        default::{DefaultCipherSuite, DefaultEngine},
        Rng,
    };
    use futures_util::{SinkExt, StreamExt, TryStreamExt};
    use tokio::net::{UnixListener, UnixStream};

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ping_pong() {
        #[derive(Clone, Debug, Serialize, Deserialize)]
        struct Ping {
            v: usize,
        }
        #[derive(Clone, Debug, Serialize, Deserialize)]
        struct Pong {
            v: usize,
        }

        type CS = DefaultCipherSuite;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sock");

        let (mut eng, _) = DefaultEngine::from_entropy(Rng);
        let sk = ApiKey::<CS>::new(&mut eng);
        let pk = sk.public().unwrap();

        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(usize::MAX)
            .new_codec();
        let info = path.as_os_str().as_encoded_bytes();

        let listener = UnixListener::bind(&path).unwrap();
        let server = server::<_, _, Ping, Pong>(listener, codec.clone(), sk, info);

        tokio::spawn(async move {
            server.inspect_err(|_| {});
            while let Some(mut conn) = server.try_next().await? {
                while let Some(Ping { v }) = conn.next().await {
                    conn.send(Pong { v: v + 1 });
                }
            }
            Ok(())
        });

        let sock = UnixStream::connect(&path).await.unwrap();
        let mut client = client::<_, _, _, Pong, Ping>(sock, codec, Rng, pk, info);

        for v in 0..100 {
            client.send(Ping { v }).await.unwrap();
        }

        todo!()
    }
}
