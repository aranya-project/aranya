use core::{borrow::Borrow, error, marker::PhantomData, pin::Pin};

use aranya_crypto::{
    self as crypto,
    aead::{Aead, IndCca2, Tag},
    csprng::Csprng,
    hpke::{Hpke, Mode, OpenCtx, SealCtx, Seq},
    kdf::Kdf,
    kem::Kem,
};
use buggy::BugExt;
use bytes::{BufMut, Bytes, BytesMut};
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use tarpc::tokio_serde::{Deserializer, Serializer};

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// Unable to perform other cryptography.
    #[error("{0}")]
    Crypto(#[from] crypto::Error),

    /// Unable to encrypt a packet.
    #[error("encryption failed")]
    Encryption,

    /// Unable to decrypt a packet.
    #[error("decryption failed")]
    Decryption,

    #[error("{0}")]
    Codec(#[from] Box<dyn error::Error>),
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
    /// - `daemon` is the daemon's public key.
    /// - `codec` is the underlying codec.
    /// - `info` is contextual binding. E.g., it could be the UDS
    ///    path used to connect to the daemon.
    pub fn new<R, K, F>(
        rng: &mut R,
        daemon: &K::EncapKey,
        codec: Codec,
        info: &[u8],
    ) -> Result<Self, crypto::Error>
    where
        K: Kem,
        F: Kdf,
        R: Csprng,
    {
        let (codec, enc) = CryptoCodec::client::<R, K, F>(rng, daemon, codec, info)?;
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
pub struct ServerCodec<A, Codec, Item, SinkItem>
where
    A: Aead + IndCca2,
{
    #[pin]
    codec: CryptoCodec<A, Codec, Item, SinkItem>,
}

impl<A, Codec, SinkItem, Item> ServerCodec<A, Codec, Item, SinkItem>
where
    A: Aead + IndCca2,
{
    /// Creates a `ServerCodec`.
    ///
    /// - `codec` is the underlying codec.
    /// - `info` is contextual binding. E.g., it could be the UDS
    ///    path used to connect to the daemon.
    pub fn new<K, F>(sk: &K::DecapKey, codec: Codec, info: &[u8]) -> Result<Self, crypto::Error>
    where
        K: Kem,
        F: Kdf,
    {
        let codec = CryptoCodec::server::<K, F>(sk, codec, info)?;
        Ok(Self { codec })
    }
}

macro_rules! impl_codec {
    ($name:ident) => {
        impl<A, Codec, SinkItem, Item> Serializer<SinkItem> for $name<A, Codec, Item, SinkItem>
        where
            A: Aead + IndCca2,
            Codec: Serializer<SinkItem>,
            Codec::Error: error::Error + 'static,
        {
            type Error = CodecError;

            fn serialize(mut self: Pin<&mut Self>, item: &SinkItem) -> Result<Bytes, Self::Error> {
                self.as_mut().project().codec.serialize(item)
            }
        }

        impl<A, Codec, SinkItem, Item> Deserializer<Item> for $name<A, Codec, Item, SinkItem>
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
    };
}
impl_codec!(ServerCodec);

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
        codec: Codec,
        info: &[u8],
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
    /// - `codec` is the underlying codec.
    /// - `info` is contextual binding. E.g., it could be the UDS
    ///    path used to connect to the daemon.
    fn server<K, F>(sk: &K::DecapKey, codec: Codec, info: &[u8]) -> Result<Self, crypto::Error>
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
