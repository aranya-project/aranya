//! Encrypted transports over length-delimited frames.
//!
//! Each connection can be split into independent read/write halves for concurrent operation.
//!
//! # Rekeying
//! Rekeying is always initiated by the client. The client tracks the sequence number on its seal
//! context and triggers a rekey when it reaches half of the AEAD nonce space maximum, ensuring the
//! keys are refreshed well before exhaustion.
//!
//! When the client rekeys, it creates a new HPKE context (producing fresh seal and open halves for
//! both sides) and sends a `Rekey` message on the wire containing the HPKE encapsulation. This
//! message always precedes the next `Data` message, so by the time receives another `Data` message,
//! it's already derived the matching context from the `Rekey` message.

mod client;
mod ctx;
mod server;
#[cfg(test)]
mod tests;

use std::{error, io};

use aranya_crypto::{
    dangerous::spideroak_crypto::{
        aead::Tag,
        hpke::{OpenCtx, SealCtx, Seq},
    },
    CipherSuite,
};
use bytes::{Bytes, BytesMut};
pub use client::client;
pub(crate) use client::ClientConn;
use futures_util::{SinkExt as _, StreamExt as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub use server::server;
pub(crate) use server::ServerConn;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, FramedRead, FramedWrite, LengthDelimitedCodec};
type OwnedReadHalf = tokio::net::unix::OwnedReadHalf;
type OwnedWriteHalf = tokio::net::unix::OwnedWriteHalf;

fn other<E>(err: E) -> io::Error
where
    E: Into<Box<dyn error::Error + Send + Sync>>,
{
    io::Error::other(err)
}

/// Identifies which side of the connection produced a message.
///
/// Used to construct the addition authenticated data (AD) to AEAD encryption, ensuring client and
/// server messages are domain-separated.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Side {
    Server,
    Client,
}

/// A message sent by the client to the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum ClientMsg {
    Data(Data),
    Rekey(Rekey),
}

/// A message sent by the server to the client.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum ServerMsg {
    Data(Data),
}

/// An encrypted payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Data {
    /// The position of this ciphertext in the message stream.
    seq: u64,
    /// The ciphertext.
    ciphertext: BytesMut,
    /// The authentication tag.
    tag: Bytes,
}

/// Instructs the server to derive a new encryption context.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Rekey {
    /// The HPKE peer encapsulation.
    enc: Bytes,
}

/// Generates the additional authenticated data (AD) for encryption.
///
/// Includes the sequence number, per [RFC 9180 §9.7.1].
///
/// [RFC 9180 §9.7.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7.1
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

/// Serialize, encrypt, and authenticate `item`, returning the ciphertext.
///
/// `side` represents the current side performing the encryption.
fn seal<CS: CipherSuite, T: Serialize>(
    ctx: &mut SealCtx<<CS as CipherSuite>::Aead>,
    item: &T,
    side: Side,
) -> io::Result<Data> {
    let serialized = postcard::to_allocvec(item).map_err(other)?;
    let mut plaintext = BytesMut::from(serialized.as_slice());
    let mut tag = BytesMut::from(&*Tag::<CS::Aead>::default());
    let ad = auth_data(ctx.seq(), side);
    let seq = ctx
        .seal_in_place(&mut plaintext, &mut tag, &ad)
        .map_err(other)?;
    Ok(Data {
        seq: seq.to_u64(),
        ciphertext: plaintext,
        tag: tag.freeze(),
    })
}

/// Decrypt, authenticate, and deserialize `data`, returning the resulting `Item`.
///
/// `side` represents the side that created `data`.
fn open<CS: CipherSuite, T: DeserializeOwned>(
    ctx: &mut OpenCtx<<CS as CipherSuite>::Aead>,
    data: Data,
    side: Side,
) -> io::Result<T> {
    let Data {
        seq,
        mut ciphertext,
        tag,
    } = data;
    let ad = auth_data(Seq::new(seq), side);
    ctx.open_in_place_at(&mut ciphertext, &tag, &ad, Seq::new(seq))
        .map_err(other)?;
    let item = postcard::from_bytes(&ciphertext).map_err(other)?;
    Ok(item)
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

/// Receive a length-delimited frame and deserialize it from a read-only half.
async fn frame_recv_read<T: DeserializeOwned>(
    framed: &mut FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
) -> io::Result<Option<T>> {
    let Some(frame) = framed.next().await else {
        return Ok(None);
    };
    let msg = postcard::from_bytes(&frame?).map_err(other)?;
    Ok(Some(msg))
}

/// Serialize a message and send it as a length-delimited frame on a write-only half.
async fn frame_send_write<T: Serialize>(
    framed: &mut FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
    msg: T,
) -> io::Result<()> {
    let bytes = postcard::to_allocvec(&msg).map_err(other)?;
    framed.send(Bytes::from(bytes)).await
}
