use core::{
    borrow::Borrow,
    error,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    pin::{pin, Pin},
    task::{Context, Poll},
};
use std::sync::Arc;

use aranya_crypto::{
    self as crypto,
    aead::{Aead, IndCca2, OpenError, Tag},
    csprng::Csprng,
    hpke::{Hpke, HpkeError, Mode, OpenCtx, SealCtx, Seq},
    import::Import,
    kdf::Kdf,
    kem::Kem,
};
use buggy::{Bug, BugExt};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{ready, Sink, Stream};
use pin_project::pin_project;
use tarpc::{
    tokio_serde::{Deserializer, Serializer},
    tokio_util::codec::{
        length_delimited::{Builder, LengthDelimitedCodec},
        Framed,
    },
};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// An internal bug.
    #[error("{0}")]
    Bug(#[from] Bug),

    /// Unable to perform other cryptography.
    #[error("{0}")]
    Crypto(#[from] Arc<crypto::Error>),

    /// Unable to encrypt a packet.
    #[error("encryption failed")]
    Encryption,

    /// Unable to decrypt a packet.
    #[error("decryption failed")]
    Decryption,

    #[error("{0}")]
    Codec(#[from] Box<dyn error::Error>),
}

impl From<crypto::Error> for CodecError {
    fn from(err: crypto::Error) -> Self {
        Self::Crypto(Arc::new(err))
    }
}

/// A tarpc `serde_transport` codec that encrypts data for the
/// server.
#[pin_project]
pub struct ClientCodec<A, Codec, Item, SinkItem>
where
    A: Aead + IndCca2,
{
    #[pin]
    codec: CryptoCodec<A, Codec, Item, SinkItem>,
    enc: Option<Vec<u8>>,
}

impl<A, Codec, SinkItem, Item> ClientCodec<A, Codec, Item, SinkItem>
where
    A: Aead + IndCca2,
{
    /// Creates a `ClientCodec`.
    ///
    /// - `pk` is the daemon's public key.
    /// - `codec` is the underlying codec.
    /// - `info` is contextual binding. E.g., it could be the UDS
    ///    path used to connect to the daemon.
    pub fn new<R, K, F>(
        rng: &mut R,
        pk: &K::EncapKey,
        codec: Codec,
        info: &[u8],
    ) -> Result<Self, crypto::Error>
    where
        K: Kem,
        F: Kdf,
        R: Csprng,
    {
        let (codec, enc) = CryptoCodec::client::<R, K, F>(rng, pk, info, codec)?;
        Ok(Self {
            codec,
            enc: Some(enc),
        })
    }
}

impl<A, Codec, SinkItem, Item> Serializer<SinkItem> for ClientCodec<A, Codec, Item, SinkItem>
where
    A: Aead + IndCca2,
    Codec: Serializer<SinkItem>,
    Codec::Error: error::Error + 'static,
{
    type Error = CodecError;

    fn serialize(mut self: Pin<&mut Self>, item: &SinkItem) -> Result<Bytes, Self::Error> {
        let mut bytes: BytesMut = self.as_mut().project().codec.serialize(item)?.into();
        let Some(enc) = self.as_mut().project().enc.take() else {
            return Ok(bytes.into());
        };
        // bytes || enc || len(enc)
        bytes.extend_from_slice(&enc);
        bytes.put_u64_le(enc.len() as u64);
        Ok(bytes.into())
    }
}

impl<A, Codec, SinkItem, Item> Deserializer<Item> for ClientCodec<A, Codec, Item, SinkItem>
where
    A: Aead + IndCca2,
    Codec: Deserializer<Item>,
    Codec::Error: error::Error + 'static,
{
    type Error = CodecError;

    fn deserialize(mut self: Pin<&mut Self>, src: &BytesMut) -> Result<Item, Self::Error> {
        self.as_mut().project().codec.deserialize(src)
    }
}

/// A tarpc `serde_transport` codec that encrypts data for the
/// server.
#[pin_project]
pub struct ServerCodec<K, F, A, Codec, Item, SinkItem>
where
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
{
    // We can't do much with Pin<Result<...>>, so split it into
    // two separate fields.
    #[pin]
    codec: Option<CryptoCodec<A, Codec, Item, SinkItem>>,
    err: Option<Arc<crypto::Error>>,

    inner: Option<Codec>,
    info: Vec<u8>,
    sk: K::DecapKey,
    _marker: PhantomData<fn() -> F>,
}

impl<K, F, A, Codec, SinkItem, Item> ServerCodec<K, F, A, Codec, Item, SinkItem>
where
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
{
    /// Creates a `ServerCodec`.
    ///
    /// - `codec` is the underlying codec.
    /// - `info` is contextual binding. E.g., it could be the UDS
    ///    path used to connect to the daemon.
    pub fn new(sk: K::DecapKey, codec: Codec, info: &[u8]) -> Result<Self, crypto::Error> {
        Ok(Self {
            codec: None,
            err: None,
            inner: Some(codec),
            info: info.to_vec(),
            sk,
            _marker: PhantomData,
        })
    }

    fn check(&self) -> Result<(), CodecError> {
        match self.err.as_ref() {
            Some(err) => Err(Arc::clone(err).into()),
            None => Ok(()),
        }
    }
}

impl<K, F, A, Codec, SinkItem, Item> Serializer<SinkItem>
    for ServerCodec<K, F, A, Codec, Item, SinkItem>
where
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
    Codec: Serializer<SinkItem>,
    Codec::Error: error::Error + 'static,
{
    type Error = CodecError;

    fn serialize(mut self: Pin<&mut Self>, item: &SinkItem) -> Result<Bytes, Self::Error> {
        self.check()?;

        let codec = self
            .as_mut()
            .project()
            .codec
            .as_pin_mut()
            .assume("`codec` should be `Some`")?;
        codec.serialize(item)
    }
}

impl<K, F, A, Codec, SinkItem, Item> Deserializer<Item>
    for ServerCodec<K, F, A, Codec, Item, SinkItem>
where
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
    Codec: Deserializer<Item>,
    Codec::Error: error::Error + 'static,
{
    type Error = CodecError;

    fn deserialize(mut self: Pin<&mut Self>, src: &BytesMut) -> Result<Item, Self::Error> {
        self.check()?;

        if self.codec.is_none() {
            // `src` should have the following layout
            //    bytes || enc || len(enc)
            let (head, tail) = src
                .split_last_chunk()
                .assume("`src` should be at least 8 bytes")?;
            let len =
                usize::try_from(u64::from_le_bytes(*tail)).assume("`len` should fit in a `u64`")?;
            let enc_idx = head
                .len()
                .checked_sub(len)
                .assume("should have at least `len` bytes")?;
            let (data, enc) = head
                .split_at_checked(enc_idx)
                .assume("`enc_idx` is in range")?;
            let enc = K::Encap::import(enc).map_err(crypto::Error::from)?;

            let inner = self
                .as_mut()
                .project()
                .inner
                .take()
                .assume("`inner` should be `None`")?;
            let codec = CryptoCodec::server::<K, F>(&self.sk, &enc, &self.info, inner)?;
            self.as_mut().project().codec.set(Some(codec));

            let codec = self
                .as_mut()
                .project()
                .codec
                .as_pin_mut()
                .assume("`codec` should be `Some`")?;
            return codec.deserialize(&BytesMut::from(data));
        }

        let codec = self
            .as_mut()
            .project()
            .codec
            .as_pin_mut()
            .assume("`codec` should be `Some`")?;
        codec.deserialize(src)
    }
}

/// A tarpc `serde_transport` codec that encrypts data for the
/// server.
#[pin_project]
struct CryptoCodec<A, Codec, Item, SinkItem>
where
    A: Aead + IndCca2,
{
    seal: SealCtx<A>,
    open: OpenCtx<A>,
    #[pin]
    codec: Codec,
    _marker: PhantomData<fn() -> (Item, SinkItem)>,
}

impl<A, Codec, SinkItem, Item> CryptoCodec<A, Codec, Item, SinkItem>
where
    A: Aead + IndCca2,
{
    /// Creates a `CryptoCodec` for a client.
    ///
    /// - `daemon` is the daemon's public key.
    /// - `codec` is the underlying codec.
    /// - `info` is contextual binding. E.g., it could be the UDS
    ///    path used to connect to the daemon.
    fn client<R, K, F>(
        rng: &mut R,
        pk: &K::EncapKey,
        info: &[u8],
        codec: Codec,
    ) -> Result<(Self, Vec<u8>), crypto::Error>
    where
        K: Kem,
        F: Kdf,
        R: Csprng,
    {
        let (enc, send) = Hpke::<K, F, A>::setup_send(rng, Mode::Base, pk, info)?;
        let (open_key, open_nonce) = {
            let key = send.export(b"ipc resp key")?;
            let nonce = send.export(b"ipc resp nonce")?;
            (key, nonce)
        };
        let (seal_key, seal_nonce) = send
            .into_raw_parts()
            .assume("should be able to decompose `SendCtx`")?;
        let seal = SealCtx::new(&seal_key, &seal_nonce, Seq::ZERO)?;
        let open = OpenCtx::new(&open_key, &open_nonce, Seq::ZERO)?;
        let enc = enc.borrow().to_vec();
        let codec = Self {
            seal,
            open,
            codec,
            _marker: PhantomData,
        };
        Ok((codec, enc))
    }

    /// Creates a `CryptoCodec` for a client.
    ///
    /// - `sk` is the daemon's secret key.
    /// - `enc` is the encapsulation from the client.
    /// - `codec` is the underlying codec.
    /// - `info` is contextual binding. E.g., it could be the UDS
    ///    path used to connect to the daemon.
    fn server<K, F>(
        sk: &K::DecapKey,
        enc: &K::Encap,
        info: &[u8],
        codec: Codec,
    ) -> Result<Self, crypto::Error>
    where
        K: Kem,
        F: Kdf,
    {
        let recv = Hpke::<K, F, A>::setup_recv(Mode::Base, enc, sk, info)?;
        let (open_key, open_nonce) = {
            let key = recv.export(b"ipc resp key")?;
            let nonce = recv.export(b"ipc resp nonce")?;
            (key, nonce)
        };
        let (seal_key, seal_nonce) = recv
            .into_raw_parts()
            .assume("should be able to decompose `SendCtx`")?;
        let seal = SealCtx::new(&seal_key, &seal_nonce, Seq::ZERO)?;
        let open = OpenCtx::new(&open_key, &open_nonce, Seq::ZERO)?;
        Ok(Self {
            seal,
            open,
            codec,
            _marker: PhantomData,
        })
    }
}

impl<A, Codec, SinkItem, Item> Serializer<SinkItem> for CryptoCodec<A, Codec, Item, SinkItem>
where
    A: Aead + IndCca2,
    Codec: Serializer<SinkItem>,
    Codec::Error: error::Error + 'static,
{
    type Error = CodecError;

    fn serialize(mut self: Pin<&mut Self>, item: &SinkItem) -> Result<Bytes, Self::Error> {
        let mut bytes: BytesMut = self
            .as_mut()
            .project()
            .codec
            .serialize(item)
            .map_err(|err| CodecError::Codec(Box::new(err)))?
            .into();
        let mut tag = Tag::<A>::default();
        self.as_mut()
            .project()
            .seal
            .seal_in_place(&mut bytes, &mut tag, &[])
            .map_err(|_| CodecError::Encryption)?;
        bytes.extend_from_slice(&tag);
        Ok(bytes.into())
    }
}

impl<A, Codec, SinkItem, Item> Deserializer<Item> for CryptoCodec<A, Codec, Item, SinkItem>
where
    A: Aead + IndCca2,
    Codec: Deserializer<Item>,
    Codec::Error: error::Error + 'static,
{
    type Error = CodecError;

    fn deserialize(mut self: Pin<&mut Self>, src: &BytesMut) -> Result<Item, Self::Error> {
        let mut data = src.clone();
        let tag_idx = data
            .len()
            .checked_sub(A::OVERHEAD)
            .ok_or(CodecError::Decryption)?;
        let tag = data.split_off(tag_idx);
        self.as_mut()
            .project()
            .open
            .open_in_place(&mut data, &tag, &[])
            .map_err(|_| CodecError::Decryption)?;
        let item = self
            .as_mut()
            .project()
            .codec
            .deserialize(&data)
            .map_err(|err| CodecError::Codec(Box::new(err)))?;
        Ok(item)
    }
}

#[cfg(unix)]
#[cfg_attr(docsrs, doc(cfg(unix)))]
pub mod unix {
    use core::future::Future;
    use std::path::Path;

    use serde::{Deserialize, Serialize};
    use tarpc::{
        serde_transport::{self, Transport},
        tokio_util::codec::{length_delimited::Builder, LengthDelimitedCodec},
    };
    use tokio::net::UnixStream;

    use super::*;

    /// Connects to socket named by `path`, wrapping the
    /// connection in an encrypted Unix Domain Socket transport.
    pub fn connect<P, R, K, F, A, Item, SinkItem, Codec, CodecFn>(
        path: P,
        rng: &mut R,
        pk: &K::EncapKey,
        codec_fn: CodecFn,
    ) -> UnixConnect<impl Future<Output = io::Result<UnixStream>>, Item, SinkItem, CodecFn>
    where
        P: AsRef<Path>,
        R: Csprng,
        K: Kem,
        F: Kdf,
        A: Aead + IndCca2,
        Item: for<'de> Deserialize<'de>,
        SinkItem: Serialize,
        Codec: Serializer<SinkItem> + Deserializer<Item>,
        CodecFn: Fn() -> Codec,
    {
        UnixConnect {
            inner: UnixStream::connect(path.as_ref()),
            rng,
            pk,
            info: path.as_ref().as_os_str().as_encoded_bytes(),
            codec_fn,
            config: LengthDelimitedCodec::builder(),
            _marker: PhantomData,
        }
    }

    /// A connection Future that also exposes the
    /// length-delimited framing config.
    #[must_use]
    #[pin_project]
    pub struct UnixConnect<'a, T, R, K, F, A, Item, SinkItem, CodecFn>
    where
        K: Kem,
    {
        #[pin]
        inner: T,
        rng: &'a mut R,
        pk: &'a K::EncapKey,
        info: &'a [u8],
        codec_fn: CodecFn,
        config: Builder,
        _marker: PhantomData<fn() -> (F, A, Item, SinkItem)>,
    }

    impl<T, R, K, F, A, Item, SinkItem, CodecFn> UnixConnect<'_, T, R, K, F, A, Item, SinkItem, CodecFn>
    where
        K: Kem,
    {
        /// Returns an immutable reference to the
        /// length-delimited codec's config.
        pub fn config(&self) -> &Builder {
            &self.config
        }

        /// Returns a mutable reference to the length-delimited
        /// codec's config.
        pub fn config_mut(&mut self) -> &mut Builder {
            &mut self.config
        }
    }

    impl<T, R, K, F, A, Item, SinkItem, Codec, CodecFn> Future
        for UnixConnect<'_, T, R, K, F, A, Item, SinkItem, CodecFn>
    where
        R: Csprng,
        K: Kem,
        F: Kdf,
        A: Aead + IndCca2,
        T: Future<Output = io::Result<UnixStream>>,
        Item: for<'de> Deserialize<'de>,
        SinkItem: Serialize,
        Codec: Serializer<SinkItem> + Deserializer<Item>,
        CodecFn: Fn() -> Codec,
    {
        type Output = io::Result<Transport<CryptIoClient<UnixStream, A>, Item, SinkItem, Codec>>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let inner = ready!(self.as_mut().project().inner.poll(cx))?;

            let codec = self.config.new_codec();

            let this = self.as_mut().project();
            let io =
                CryptIoClient::new::<R, K, F>(inner, codec.clone(), this.rng, this.pk, this.info)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            Poll::Ready(Ok(serde_transport::new(
                Framed::new(io, codec),
                (this.codec_fn)(),
            )))
        }
    }
}

#[pin_project]
pub struct CryptIoClient<S, A>
where
    A: Aead + IndCca2,
{
    #[pin]
    io: CryptIo<S, A>,
    enc: Option<Vec<u8>>,
}

impl<S, A> CryptIoClient<S, A>
where
    S: AsyncRead + AsyncWrite,
    A: Aead + IndCca2,
{
    fn new<R, K, F>(
        io: S,
        codec: LengthDelimitedCodec,
        rng: &mut R,
        pk: &K::EncapKey,
        info: &[u8],
    ) -> Result<Self, HpkeError>
    where
        K: Kem,
        F: Kdf,
        R: Csprng,
    {
        let (io, enc) = CryptIo::client::<R, K, F>(io, codec, rng, pk, info)?;
        Ok(Self {
            io,
            enc: Some(enc.borrow().to_vec()),
        })
    }
}

impl<S, A> AsyncRead for CryptIoClient<S, A>
where
    S: AsyncRead,
    A: Aead + IndCca2,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().io.poll_read(cx, buf)
    }
}

impl<S, A> AsyncWrite for CryptIoClient<S, A>
where
    S: AsyncRead + AsyncWrite,
    A: Aead + IndCca2,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // TODO: handle `enc`
        self.project().io.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().io.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().io.poll_shutdown(cx)
    }
}

#[pin_project]
pub struct CryptIo<S, A>
where
    A: Aead + IndCca2,
{
    #[pin]
    stream: Framed<S, LengthDelimitedCodec>,
    /// Set to true when `stream.poll_next` returns `None`.
    eof: bool,
    /// Unread plaintext bytes.
    pt: BytesMut,
    /// Scratch space for outgoing data.
    ///
    /// If it has a non-zero length then it contains plaintext
    /// data.
    ct: BytesMut,
    blah: BytesMut,
    chunk_size: usize,
    seal: SealCtx<A>,
    open: OpenCtx<A>,
}

impl<S, A> CryptIo<S, A>
where
    S: AsyncRead + AsyncWrite,
    A: Aead + IndCca2,
{
    fn client<R, K, F>(
        io: S,
        mut codec: LengthDelimitedCodec,
        rng: &mut R,
        pk: &K::EncapKey,
        info: &[u8],
    ) -> Result<(Self, K::Encap), HpkeError>
    where
        K: Kem,
        F: Kdf,
        R: Csprng,
    {
        let (enc, send) = Hpke::<K, F, A>::setup_send(rng, Mode::Base, pk, info)?;
        let (open_key, open_nonce) = {
            let key = send.export(b"ipc resp key")?;
            let nonce = send.export(b"ipc resp nonce")?;
            (key, nonce)
        };
        let (seal_key, seal_nonce) = send
            .into_raw_parts()
            .assume("should be able to decompose `SendCtx`")?;
        let seal = SealCtx::new(&seal_key, &seal_nonce, Seq::ZERO)?;
        let open = OpenCtx::new(&open_key, &open_nonce, Seq::ZERO)?;

        // Reduce the frame length to accomodate encryption
        // overhead.
        let max_frame_size = codec
            .max_frame_length()
            .checked_sub(A::OVERHEAD)
            .assume("max frame size is greater than the AEAD overhead")?;
        codec.set_max_frame_length(max_frame_size);

        // Set the chunk size to something reasonable.
        let chunk_size = codec
            .max_frame_length()
            .min(4096)
            .checked_sub(A::OVERHEAD)
            .assume("chunk size is greater than the AEAD overhead")?;

        let io = Self {
            stream: Framed::new(io, codec),
            eof: false,
            pt: BytesMut::new(),
            ct: BytesMut::with_capacity(chunk_size + A::OVERHEAD),
            blah: BytesMut::new(),
            chunk_size,
            seal,
            open,
        };
        Ok((io, enc))
    }
}

impl<S, A> CryptIo<S, A>
where
    S: AsyncWrite,
    A: Aead + IndCca2,
{
    fn seal_and_send(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let this = self.as_mut().project();

        let mut tag = Tag::<A>::default();
        this.seal
            .seal_in_place(&mut this.ct, &mut tag, &[])
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

        ready!(this.stream.as_mut().poll_ready(cx))?;

        this.ct.put_slice(&tag);

        // TODO(eric): It kinda sucks to allocate each time.
        this.stream.as_mut().start_send(this.ct.clone().freeze());
    }
}

impl<S, A> AsyncRead for CryptIo<S, A>
where
    S: AsyncRead,
    A: Aead + IndCca2,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.eof {
            return Poll::Ready(Ok(()));
        }

        let mut this = self.project();
        while buf.remaining() > 0 {
            debug_assert!(this.pt.is_empty());

            if this.pt.is_empty() {
                let item = ready!(this.stream.as_mut().poll_next(cx)?);
                let Some(mut data) = item else {
                    *this.eof = true;
                    return Poll::Ready(Ok(()));
                };
                let tag_idx = data.len().checked_sub(A::OVERHEAD).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Other, OpenError::Authentication)
                })?;
                let tag = data.split_off(tag_idx);
                this.open
                    .open_in_place(&mut data, &tag, &[])
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
                *this.pt = data;
            }

            let n = buf.remaining().min(this.pt.len());
            let chunk = this.pt.split_to(n);
            buf.put_slice(&chunk);
        }

        Poll::Ready(Ok(()))
    }
}

impl<S, A> AsyncWrite for CryptIo<S, A>
where
    S: AsyncWrite,
    A: Aead + IndCca2,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut nw = 0;

        let chunk_size = self.chunk_size;
        let pt_max = chunk_size - A::OVERHEAD;

        // TODO: blah

        if !self.ct.is_empty() {
            // How many bytes to we need to fill the buffer?
            let need = pt_max
                .checked_sub(self.ct.len())
                .assume("`ct` is less than `pt_max`")
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            let (head, tail) = buf.split_at(buf.len().min(need));
            self.as_mut().project().ct.put_slice(head);
            if self.ct.len() < pt_max {
                debug_assert!(tail.is_empty());

                // Not enough to encrypt yet.
                return Poll::Ready(Ok(head.len()));
            }

            match self.as_mut().seal_and_send(cx)? {
                Poll::Ready(n) => nw += n,
                Poll::Pending => {
                    *self.as_mut().project().blah = BytesMut::from(tail);
                    return Poll::Pending;
                }
            }

            buf = tail;
        }

        let mut this = self.as_mut().project();
        let mut chunks = buf.chunks_exact(pt_max);
        for chunk in chunks.by_ref() {
            this.ct.clear();
            this.ct.put_slice(chunk);

            let mut tag = Tag::<A>::default();
            this.seal
                .seal_in_place(&mut this.ct, &mut tag, &[])
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            this.ct.put_slice(&tag);

            ready!(this.stream.as_mut().poll_ready(cx))?;
            // TODO(eric): It kinda sucks to allocate each time.
            this.stream.as_mut().start_send(this.ct.clone().freeze());
        }

        Poll::Ready(Ok(nw))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_close(cx)
    }
}
