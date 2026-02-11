use bytes::Bytes;
use futures_util::AsyncReadExt as _;
use s2n_quic::stream::{BidirectionalStream, ReceiveStream, SendStream};

use super::Error;
use crate::sync::{transport::SyncStream, SyncPeer};

pub(crate) struct QuicStream {
    peer: SyncPeer,
    recv: ReceiveStream,
    send: SendStream,
}

impl QuicStream {
    pub(crate) fn new(peer: SyncPeer, stream: BidirectionalStream) -> Self {
        let (recv, send) = stream.split();
        Self { peer, recv, send }
    }
}

#[async_trait::async_trait]
impl SyncStream for QuicStream {
    type Error = Error;

    fn peer(&self) -> SyncPeer {
        self.peer
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.send
            .send(Bytes::copy_from_slice(data))
            .await
            .map_err(Error::Send)?;
        Ok(())
    }

    async fn receive(&mut self, buffer: &mut Vec<u8>) -> Result<(), Self::Error> {
        buffer.clear();
        self.recv
            .read_to_end(buffer)
            .await
            .map_err(Error::Receive)?;
        Ok(())
    }

    async fn finish(&mut self) -> Result<(), Self::Error> {
        self.send.close().await.map_err(Error::Finish)?;
        Ok(())
    }
}
