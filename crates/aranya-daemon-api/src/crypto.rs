use core::{
    borrow::Borrow,
    error,
    marker::PhantomData,
    pin::{pin, Pin},
    task::{Context, Poll},
};

use aranya_crypto::{
    aead::{Aead, IndCca2, Tag},
    csprng::Csprng,
    hpke::{Hpke, HpkeError, Mode, OpenCtx, SealCtx, Seq},
    import::Import,
    kdf::Kdf,
    kem::Kem,
};
use buggy::BugExt;
use bytes::{Bytes, BytesMut};
use futures::{ready, Sink, Stream};
use pin_project::pin_project;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub use tarpc::tokio_util::codec::length_delimited::{Builder, LengthDelimitedCodec};
use tarpc::{
    serde_transport::{self, Transport},
    tokio_serde::{
        formats::{MessagePack, SymmetricalMessagePack},
        Deserializer, Serializer,
    },
    tokio_util::codec::Framed,
};
use tokio::io::{self, AsyncRead, AsyncWrite};

fn other<E>(err: E) -> io::Error
where
    E: Into<Box<dyn error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, err)
}

/// Creates a client-side transport.
pub async fn client<S, R, K, F, A, Item, SinkItem>(
    io: S,
    codec: LengthDelimitedCodec,
    rng: R,
    pk: K::EncapKey,
    info: &[u8],
) -> io::Result<CryptIoClient<S, R, K, F, A, Item, SinkItem>>
where
    S: AsyncRead + AsyncWrite,
    R: Csprng,
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
    Item: for<'de> Deserialize<'de>,
    SinkItem: Serialize,
{
    let inner = serde_transport::new(
        Framed::new(io, codec.clone()),
        SymmetricalMessagePack::default(),
    );
    let client = CryptIoClient {
        inner,
        rng,
        pk,
        info: info.to_vec(),
        seal: None,
        open: None,
        _marker: PhantomData,
    };
    Ok(client)
}

/// An encrypted [`Transport`][tarpc::Transport].
#[pin_project]
pub struct CryptIoClient<S, R, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    K: Kem,
    A: Aead + IndCca2,
{
    #[pin]
    inner: Transport<S, Msg, Msg, SymmetricalMessagePack<Msg>>,
    rng: R,
    pk: K::EncapKey,
    info: Vec<u8>,
    seal: Option<SealCtx<A>>,
    open: Option<OpenCtx<A>>,
    #[allow(clippy::type_complexity)]
    _marker: PhantomData<fn() -> (F, Item, SinkItem)>,
}

impl<S, R, K, F, A, Item, SinkItem> CryptIoClient<S, R, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    K: Kem,
    A: Aead + IndCca2,
    SinkItem: Serialize,
{
    fn encrypt(&mut self, item: SinkItem) -> io::Result<Data> {
        let mut codec = MessagePack::<Item, SinkItem>::default();
        let mut plaintext = BytesMut::from(pin!(codec).serialize(&item)?);
        let mut tag = BytesMut::from(&*Tag::<A>::default());
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

impl<S, R, K, F, A, Item, SinkItem> CryptIoClient<S, R, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    K: Kem,
    A: Aead + IndCca2,
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

impl<S, R, K, F, A, Item, SinkItem> CryptIoClient<S, R, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    R: Csprng,
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
{
    fn rekey(&mut self) -> Result<Hello, HpkeError> {
        let (enc, send) =
            Hpke::<K, F, A>::setup_send(&mut self.rng, Mode::Base, &self.pk, &self.info)?;
        let (open_key, open_nonce) = {
            let key = send.export(b"cryptio server seal key")?;
            let nonce = send.export(b"cryptio server seal nonce")?;
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

impl<S, R, K, F, A, Item, SinkItem> Stream for CryptIoClient<S, R, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Csprng,
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
    Item: DeserializeOwned,
{
    type Item = io::Result<Item>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let msg = ready!(self.as_mut().project().inner.poll_next(cx)?);
        let Some(msg) = msg else {
            return Poll::Ready(None);
        };
        match msg {
            Msg::Hello(_) => Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server cannot send `Hello`",
            )))),
            Msg::Data(data) => {
                let pt = self.decrypt(data)?;
                Poll::Ready(Some(Ok(pt)))
            }
            Msg::Rekey(_) => Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server cannot send `Rekey`",
            )))),
        }
    }
}

impl<S, R, K, F, A, Item, SinkItem> Sink<SinkItem> for CryptIoClient<S, R, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Csprng,
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
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
                .start_send(Msg::Hello(hello))?;
        }
        let data = self.encrypt(item)?;
        self.project().inner.start_send(Msg::Data(data))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

/// Creates a server-side transport.
pub async fn server<S, K, F, A, Item, SinkItem>(
    io: S,
    codec: LengthDelimitedCodec,
    sk: K::DecapKey,
    info: &[u8],
) -> io::Result<CryptIoServer<S, K, F, A, Item, SinkItem>>
where
    S: AsyncRead + AsyncWrite,
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
    Item: for<'de> Deserialize<'de>,
    SinkItem: Serialize,
{
    let inner = serde_transport::new(
        Framed::new(io, codec.clone()),
        SymmetricalMessagePack::default(),
    );
    Ok(CryptIoServer {
        inner,
        sk,
        info: info.to_vec(),
        seal: None,
        open: None,
        _marker: PhantomData,
    })
}

/// An encrypted [`Transport`][tarpc::Transport].
#[pin_project]
pub struct CryptIoServer<S, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    K: Kem,
    A: Aead + IndCca2,
{
    #[pin]
    inner: Transport<S, Msg, Msg, SymmetricalMessagePack<Msg>>,
    sk: K::DecapKey,
    info: Vec<u8>,
    seal: Option<SealCtx<A>>,
    open: Option<OpenCtx<A>>,
    #[allow(clippy::type_complexity)]
    _marker: PhantomData<fn() -> (F, Item, SinkItem)>,
}

impl<S, K, F, A, Item, SinkItem> CryptIoServer<S, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    K: Kem,
    A: Aead + IndCca2,
    SinkItem: Serialize,
{
    fn encrypt(&mut self, item: SinkItem) -> io::Result<Data> {
        let mut codec = MessagePack::<Item, SinkItem>::default();
        let mut plaintext = BytesMut::from(pin!(codec).serialize(&item)?);
        let mut tag = BytesMut::from(&*Tag::<A>::default());
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

impl<S, K, F, A, Item, SinkItem> CryptIoServer<S, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    K: Kem,
    A: Aead + IndCca2,
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

impl<S, K, F, A, Item, SinkItem> CryptIoServer<S, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite,
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
{
    fn rekey(&mut self, enc: &[u8]) -> Result<(), HpkeError> {
        let enc = <K::Encap as Import<_>>::import(enc)?;

        let recv = Hpke::<K, F, A>::setup_recv(Mode::Base, &enc, &self.sk, &self.info)?;
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

impl<S, K, F, A, Item, SinkItem> Stream for CryptIoServer<S, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
    Item: DeserializeOwned,
{
    type Item = io::Result<Item>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let msg = ready!(self.as_mut().project().inner.poll_next(cx)?);
        let Some(msg) = msg else {
            return Poll::Ready(None);
        };
        match msg {
            Msg::Hello(hello) => {
                self.rekey(&hello.enc).map_err(other)?;
                Poll::Pending
            }
            Msg::Data(data) => {
                let pt = self.decrypt(data)?;
                Poll::Ready(Some(Ok(pt)))
            }
            Msg::Rekey(rekey) => {
                self.rekey(&rekey.enc).map_err(other)?;
                Poll::Pending
            }
        }
    }
}

impl<S, K, F, A, Item, SinkItem> Sink<SinkItem> for CryptIoServer<S, K, F, A, Item, SinkItem>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
    SinkItem: Serialize,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        let data = self.encrypt(item)?;
        self.project().inner.start_send(Msg::Data(data))
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
enum Msg {
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
