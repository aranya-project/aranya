//! This module implements [`QuicStream`] to allow sending and receiving data to a peer.
use buggy::BugExt as _;
use bytes::Bytes;
use futures_util::AsyncReadExt as _;
use s2n_quic::stream::BidirectionalStream;

use super::{Error, SyncStream};
use crate::sync::SyncPeer;

pub(crate) struct QuicStream {
    /// The unique sync peer we're connected to.
    peer: SyncPeer,
    /// The underlying stream we use to communicate.
    stream: BidirectionalStream,
}

impl QuicStream {
    /// Creates a new [`QuicStream`].
    pub(crate) fn new(peer: SyncPeer, stream: BidirectionalStream) -> Self {
        Self { peer, stream }
    }
}

impl SyncStream for QuicStream {
    type Error = Error;

    fn peer(&self) -> SyncPeer {
        self.peer
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let len: u32 = data.len().try_into().map_err(|_| Error::MessageTooLarge)?;
        self.stream
            .send(Bytes::copy_from_slice(&len.to_be_bytes()))
            .await
            .map_err(Error::Send)?;
        self.stream
            .send(Bytes::copy_from_slice(data))
            .await
            .map_err(Error::Send)
    }

    async fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .await
            .map_err(Error::Receive)?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > buffer.len() {
            return Err(Error::MessageTooLarge);
        }

        let buf = buffer.get_mut(..len).assume("valid offset")?;
        self.stream.read_exact(buf).await.map_err(Error::Receive)?;
        Ok(len)
    }

    async fn finish(&mut self) -> Result<(), Self::Error> {
        self.stream.close().await.map_err(Error::Finish)?;
        Ok(())
    }
}
