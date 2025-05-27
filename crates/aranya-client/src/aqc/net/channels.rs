use core::task::{Context as CoreContext, Poll};

use aranya_crypto::aqc::{BidiChannelId, UniChannelId};
use aranya_daemon_api::LabelId;
use bytes::Bytes;
use futures_util::task::noop_waker;
use s2n_quic::{
    connection::Handle,
    stream::{PeerStream, ReceiveStream, SendStream},
    Connection,
};

use super::TryReceiveError;
use crate::{aqc::api::AqcChannelId, error::AqcError};

/// A channel opened by a peer.
#[derive(Debug)]
pub enum AqcPeerChannel {
    /// Used to receive data from a peer.
    Receive(AqcReceiveChannel),
    /// Used to send and receive data with a peer.
    Bidi(AqcBidiChannel),
}

impl AqcPeerChannel {
    pub(crate) fn new(label_id: LabelId, channel_id: AqcChannelId, conn: Connection) -> Self {
        match channel_id {
            AqcChannelId::Bidi(id) => {
                // Once we accept a valid connection, let's turn it into an AQC Channel that we can
                // then open an arbitrary number of streams on.
                let channel = AqcBidiChannel::new(label_id, id, conn);
                AqcPeerChannel::Bidi(channel)
            }
            AqcChannelId::Uni(id) => {
                // Once we accept a valid connection, let's turn it into an AQC Channel that we can
                // then open an arbitrary number of streams on.
                let receiver = AqcReceiveChannel::new(label_id, id, conn);
                AqcPeerChannel::Receive(receiver)
            }
        }
    }
}

/// The sending end of a unidirectional channel.
/// Allows sending data streams over a channel.
#[derive(Debug)]
pub struct AqcSenderChannel {
    pub(crate) label_id: LabelId,
    pub(crate) handle: Handle,
    pub(crate) id: UniChannelId,
}

impl AqcSenderChannel {
    /// Create a new channel with the given id and conection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub(crate) fn new(label_id: LabelId, id: UniChannelId, handle: Handle) -> Self {
        Self {
            label_id,
            id,
            handle,
        }
    }

    /// Get the channel label id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Get the channel id.
    pub fn aqc_id(&self) -> UniChannelId {
        self.id
    }

    /// Creates a new unidirectional stream for the channel.
    pub async fn create_uni_stream(&mut self) -> Result<AqcSendStream, AqcError> {
        let send = self.handle.open_send_stream().await?;
        Ok(AqcSendStream { send })
    }

    /// Close the channel if it's open. If the channel is already closed, do nothing.
    pub fn close(&mut self) {
        pub(crate) const ERROR_CODE: u32 = 0;
        self.handle.close(ERROR_CODE.into());
    }
}

impl Drop for AqcSenderChannel {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::fmt::Display for AqcSenderChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AqcSenderChannel(label_id: {}, id: {})",
            self.label_id, self.id
        )
    }
}

/// The receive end of a unidirectional channel.
/// Allows receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcReceiveChannel {
    pub(crate) label_id: LabelId,
    pub(crate) aqc_id: UniChannelId,
    pub(crate) conn: Connection,
}

impl AqcReceiveChannel {
    /// Create a new channel with the given conection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub(crate) fn new(label_id: LabelId, aqc_id: UniChannelId, conn: Connection) -> Self {
        Self {
            label_id,
            aqc_id,
            conn,
        }
    }

    /// Get the channel id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Get the aqc id.
    pub fn aqc_id(&self) -> UniChannelId {
        self.aqc_id
    }

    /// Returns the next unidirectional stream.
    pub async fn receive_uni_stream(&mut self) -> Result<AqcReceiveStream, AqcError> {
        match self.conn.accept_receive_stream().await {
            Ok(Some(stream)) => Ok(AqcReceiveStream { receive: stream }),
            Ok(None) => Err(AqcError::ConnectionClosed),
            Err(e) => Err(AqcError::ConnectionError(e)),
        }
    }

    /// Receive a unidirectional stream if one is available. If there is no stream available,
    /// return Empty. If the stream is disconnected, return Disconnected. If disconnected
    /// is returned no streams will be available until a new channel is created.
    pub fn try_receive_uni_stream(&mut self) -> Result<AqcReceiveStream, TryReceiveError> {
        let waker = noop_waker();
        let mut cx = CoreContext::from_waker(&waker);
        match self.conn.poll_accept_receive_stream(&mut cx) {
            Poll::Ready(Ok(Some(stream))) => Ok(AqcReceiveStream { receive: stream }),
            Poll::Ready(Ok(None)) => Err(TryReceiveError::Empty),
            Poll::Ready(Err(e)) => Err(TryReceiveError::Error(AqcError::ConnectionError(e))),
            Poll::Pending => Err(TryReceiveError::Empty),
        }
    }
}

/// A unique channel between two peers.
/// Allows sending and receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcBidiChannel {
    pub(crate) label_id: LabelId,
    pub(crate) aqc_id: BidiChannelId,
    pub(crate) conn: Connection,
}

impl AqcBidiChannel {
    /// Create a new bidirectional channel with the given id and conection handle.
    pub(crate) fn new(label_id: LabelId, aqc_id: BidiChannelId, conn: Connection) -> Self {
        Self {
            label_id,
            aqc_id,
            conn,
        }
    }

    /// Get the channel label id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Get the aqc id.
    pub fn aqc_id(&self) -> BidiChannelId {
        self.aqc_id
    }

    /// Returns the next available stream.
    /// If the stream is bidirectional, return a tuple of the send and receive streams.
    /// If the stream is unidirectional, return a tuple of None and the receive stream.
    pub async fn receive_stream(&mut self) -> Result<AqcPeerStream, AqcError> {
        match self.conn.accept().await {
            Ok(Some(stream)) => match stream {
                PeerStream::Bidirectional(stream) => Ok(AqcPeerStream::Bidi(AqcBidiStream(stream))),
                PeerStream::Receive(recv) => {
                    Ok(AqcPeerStream::Receive(AqcReceiveStream { receive: recv }))
                }
            },
            Ok(None) => Err(AqcError::ConnectionClosed),
            Err(e) => Err(AqcError::ConnectionError(e)),
        }
    }

    /// Receive a stream if one is available. If there is no stream available,
    /// return Empty. If the channel is closed, return Disconnected. If disconnected
    /// is returned no streams will be available until a new channel is created.
    pub fn try_receive_stream(
        &mut self,
    ) -> Result<(Option<AqcSendStream>, AqcReceiveStream), TryReceiveError> {
        let waker = noop_waker();
        let mut cx = CoreContext::from_waker(&waker);

        match self.conn.poll_accept(&mut cx) {
            Poll::Ready(Ok(Some(peer_stream))) => match peer_stream {
                PeerStream::Bidirectional(stream) => {
                    let (recv, send) = stream.split();
                    Ok((
                        Some(AqcSendStream { send }),
                        AqcReceiveStream { receive: recv },
                    ))
                }
                PeerStream::Receive(recv) => Ok((None, AqcReceiveStream { receive: recv })),
            },
            Poll::Ready(Ok(None)) => {
                // Connection closed by peer, no more streams will be accepted.
                Err(TryReceiveError::Error(AqcError::ConnectionClosed))
            }
            Poll::Ready(Err(e)) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                Err(TryReceiveError::Error(AqcError::ConnectionError(e)))
            }
            Poll::Pending => {
                // No stream is immediately available.
                Err(TryReceiveError::Empty)
            }
        }
    }

    /// Creates a new unidirectional stream for the channel.
    pub async fn create_uni_stream(&mut self) -> Result<AqcSendStream, AqcError> {
        let send = self.conn.open_send_stream().await?;
        Ok(AqcSendStream { send })
    }

    /// Creates a new bidirectional stream for the channel.
    pub async fn create_bidi_stream(&mut self) -> Result<AqcBidiStream, AqcError> {
        let bidi = self.conn.open_bidirectional_stream().await?;
        Ok(AqcBidiStream(bidi))
    }

    /// Close the channel if it's open. If the channel is already closed, do nothing.
    pub fn close(&mut self) {
        pub(crate) const ERROR_CODE: u32 = 0;
        self.conn.close(ERROR_CODE.into());
    }
}

impl Drop for AqcBidiChannel {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::fmt::Display for AqcBidiChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AqcBidirectionalChannel(label_id: {}, aqc_id: {})",
            self.label_id, self.aqc_id
        )
    }
}

/// Used to send and receive data with a peer.
pub struct AqcBidiStream(s2n_quic::stream::BidirectionalStream);

impl AqcBidiStream {
    /// Send data to the given stream.
    pub async fn send(&mut self, data: Bytes) -> Result<(), AqcError> {
        self.0.send(data).await?;
        Ok(())
    }

    /// Close the stream.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        self.0.close().await?;
        Ok(())
    }

    /// Receive the next available data from a stream. If the stream has
    /// been closed, return None.
    ///
    /// This method will block until data is available to return.
    /// The data is not guaranteed to be complete, and may need to be called
    /// multiple times to receive all data from a message.
    pub async fn receive(&mut self) -> Result<Option<Bytes>, AqcError> {
        Ok(self.0.receive().await?)
    }

    /// Receive the next available data from a stream.
    ///
    /// This method will return immediately with an error if there is no data available.
    /// The errors are:
    /// - Empty: No data available.
    /// - Closed: The stream is closed.
    pub fn try_receive(&mut self) -> Result<Bytes, TryReceiveError> {
        let waker = noop_waker();
        let mut cx = CoreContext::from_waker(&waker);
        match self.0.poll_receive(&mut cx) {
            Poll::Ready(Ok(Some(chunk))) => Ok(chunk),
            Poll::Ready(Ok(None)) => Err(TryReceiveError::Closed),
            Poll::Ready(Err(_e)) => Err(TryReceiveError::Closed),
            Poll::Pending => Err(TryReceiveError::Empty),
        }
    }
}

/// Used to receive data from a peer.
pub struct AqcReceiveStream {
    pub(crate) receive: ReceiveStream,
}

impl AqcReceiveStream {
    /// Receive the next available data from a stream. If the stream has
    /// been closed, return None.
    ///
    /// This method will block until data is available to return.
    /// The data is not guaranteed to be complete, and may need to be called
    /// multiple times to receive all data from a message.
    pub async fn receive(&mut self) -> Result<Option<Bytes>, AqcError> {
        Ok(self.receive.receive().await?)
    }

    /// Receive the next available data from a stream.
    ///
    /// This method will return immediately with an error if there is no data available.
    /// The errors are:
    /// - Empty: No data available.
    /// - Closed: The stream is closed.
    pub fn try_receive(&mut self) -> Result<Bytes, TryReceiveError> {
        let waker = noop_waker();
        let mut cx = CoreContext::from_waker(&waker);
        match self.receive.poll_receive(&mut cx) {
            Poll::Ready(Ok(Some(chunk))) => Ok(chunk),
            Poll::Ready(Ok(None)) => Err(TryReceiveError::Closed),
            Poll::Ready(Err(_e)) => Err(TryReceiveError::Closed),
            Poll::Pending => Err(TryReceiveError::Empty),
        }
    }
}

/// Used to send data to a peer.
pub struct AqcSendStream {
    pub(crate) send: SendStream,
}

impl AqcSendStream {
    /// Send data to the given stream.
    pub async fn send(&mut self, data: Bytes) -> Result<(), AqcError> {
        self.send.send(data).await?;
        Ok(())
    }
    /// Close the stream.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        self.send.close().await?;
        Ok(())
    }
}

/// A stream accepted from a peer.
pub enum AqcPeerStream {
    /// A bidirectional stream.
    Bidi(AqcBidiStream),
    /// A receive-only stream.
    Receive(AqcReceiveStream),
}

impl AqcPeerStream {
    /// Tries to converts the peer stream into a bidi stream.
    #[allow(clippy::result_large_err)]
    pub fn into_bidi(self) -> Result<AqcBidiStream, Self> {
        if let Self::Bidi(s) = self {
            Ok(s)
        } else {
            Err(self)
        }
    }

    /// Tries to converts the peer stream into a bidi stream.
    #[allow(clippy::result_large_err)]
    pub fn into_receive(self) -> Result<AqcReceiveStream, Self> {
        if let Self::Receive(s) = self {
            Ok(s)
        } else {
            Err(self)
        }
    }
}
