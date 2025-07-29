use core::task::{Context, Poll, Waker};
use std::sync::Arc;

use aranya_crypto::aqc::{BidiChannelId, UniChannelId};
use aranya_daemon_api::LabelId;
use bytes::Bytes;
use tracing::debug;

use super::{AqcChannelId, TryReceiveError};
use crate::{
    aqc::{
        crypto::{ClientPresharedKeys, ServerPresharedKeys},
        net::PskIdentity,
    },
    error::AqcError,
};
mod s2n {
    pub use s2n_quic::{
        connection::Handle,
        stream::{BidirectionalStream, PeerStream, ReceiveStream, SendStream},
        Connection,
    };
}

/// AQC connection close error codes.
#[derive(Debug, Copy, Clone)]
enum ConnectionCloseError {
    /// The AQC channel has been closed by the peer when closing the QUIC connection.
    ChannelClosed,
}

/// AQC Channel Keys.
#[derive(Debug)]
pub struct ChannelKeys {
    client_keys: Arc<ClientPresharedKeys>,
    server_keys: Arc<ServerPresharedKeys>,
}

impl ChannelKeys {
    pub fn new(
        client_keys: Arc<ClientPresharedKeys>,
        server_keys: Arc<ServerPresharedKeys>,
    ) -> Self {
        Self {
            client_keys,
            server_keys,
        }
    }

    pub fn zeroize_psks(&self, identities: &[PskIdentity]) {
        self.client_keys.zeroize_psks(identities);
        self.server_keys.zeroize_psks(identities);
    }
}

/// A channel opened by a peer.
#[derive(Debug)]
pub enum AqcPeerChannel {
    /// Used to receive data from a peer.
    Receive(AqcReceiveChannel),
    /// Used to send and receive data with a peer.
    Bidi(AqcBidiChannel),
}

impl AqcPeerChannel {
    pub(super) fn new(
        label_id: LabelId,
        channel_id: AqcChannelId,
        conn: s2n::Connection,
        identity: Vec<u8>,
        keys: ChannelKeys,
    ) -> Self {
        match channel_id {
            AqcChannelId::Bidi(id) => {
                // Once we accept a valid connection, let's turn it into an AQC Channel that we can
                // then open an arbitrary number of streams on.
                let channel = AqcBidiChannel::new(label_id, id, conn, vec![identity], keys);
                AqcPeerChannel::Bidi(channel)
            }
            AqcChannelId::Uni(id) => {
                // Once we accept a valid connection, let's turn it into an AQC Channel that we can
                // then open an arbitrary number of streams on.
                let receiver = AqcReceiveChannel::new(label_id, id, conn, vec![identity], keys);
                AqcPeerChannel::Receive(receiver)
            }
        }
    }
}

/// The sending end of a unidirectional channel.
/// Allows sending data streams over a channel.
#[derive(Debug)]
pub struct AqcSendChannel {
    label_id: LabelId,
    handle: s2n::Handle,
    id: UniChannelId,
    identities: Vec<PskIdentity>,
    keys: ChannelKeys,
}

impl AqcSendChannel {
    /// Create a new channel with the given id and connection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub(super) fn new<I>(
        label_id: LabelId,
        id: UniChannelId,
        handle: s2n::Handle,
        identities: I,
        keys: ChannelKeys,
    ) -> Self
    where
        I: IntoIterator<Item = PskIdentity>,
    {
        Self {
            label_id,
            id,
            handle,
            identities: identities.into_iter().collect(),
            keys,
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
        Ok(AqcSendStream(send))
    }

    /// Close the channel if it's open. If the channel is already closed, do nothing.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        debug!("closing aqc send channel");
        const ERROR_CODE: u32 = ConnectionCloseError::ChannelClosed as u32;
        self.handle.close(ERROR_CODE.into());
        self.keys.zeroize_psks(&self.identities);

        Ok(())
    }
}

impl Drop for AqcSendChannel {
    fn drop(&mut self) {
        debug!("dropping aqc send channel");
        let _ = futures_lite::future::block_on(self.close());
    }
}

/// The receive end of a unidirectional channel.
/// Allows receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcReceiveChannel {
    label_id: LabelId,
    aqc_id: UniChannelId,
    conn: s2n::Connection,
    identities: Vec<PskIdentity>,
    keys: ChannelKeys,
}

impl AqcReceiveChannel {
    /// Create a new channel with the given connection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub(super) fn new<I>(
        label_id: LabelId,
        aqc_id: UniChannelId,
        conn: s2n::Connection,
        identities: I,
        keys: ChannelKeys,
    ) -> Self
    where
        I: IntoIterator<Item = PskIdentity>,
    {
        Self {
            label_id,
            aqc_id,
            conn,
            identities: identities.into_iter().collect(),
            keys,
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
            Ok(Some(stream)) => Ok(AqcReceiveStream(stream)),
            Ok(None) => {
                // Connection closed by peer, no more streams will be accepted.
                Err(AqcError::ConnectionClosed)
            }
            Err(e) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                if let s2n_quic::connection::Error::Transport { code, .. } = e {
                    if code.as_u64() == ConnectionCloseError::ChannelClosed as u64 {
                        let _ = self.close().await;
                    }
                }
                Err(AqcError::ConnectionError(e))
            }
        }
    }

    /// Receive a unidirectional stream if one is available. If there is no stream available,
    /// return Empty. If the stream is disconnected, return Disconnected. If disconnected
    /// is returned no streams will be available until a new channel is created.
    pub fn try_receive_uni_stream(&mut self) -> Result<AqcReceiveStream, TryReceiveError> {
        let mut cx = Context::from_waker(Waker::noop());
        match self.conn.poll_accept_receive_stream(&mut cx) {
            Poll::Ready(Ok(Some(stream))) => Ok(AqcReceiveStream(stream)),
            Poll::Ready(Ok(None)) => {
                // Connection closed by peer, no more streams will be accepted.
                Err(TryReceiveError::Error(AqcError::ConnectionClosed))
            }
            Poll::Ready(Err(e)) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                if let s2n_quic::connection::Error::Transport { code, .. } = e {
                    if code.as_u64() == ConnectionCloseError::ChannelClosed as u64 {
                        let _ = futures_lite::future::block_on(self.close());
                    }
                }
                let _ = futures_lite::future::block_on(self.close());
                Err(TryReceiveError::Error(AqcError::ConnectionError(e)))
            }
            Poll::Pending => Err(TryReceiveError::Empty),
        }
    }

    /// Close the receive channel.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        debug!("closing aqc receive channel");
        const ERROR_CODE: u32 = ConnectionCloseError::ChannelClosed as u32;
        self.conn.close(ERROR_CODE.into());
        self.keys.zeroize_psks(&self.identities);

        Ok(())
    }
}

impl Drop for AqcReceiveChannel {
    fn drop(&mut self) {
        debug!("dropping aqc receive channel");
        let _ = futures_lite::future::block_on(self.close());
    }
}

/// A unique channel between two peers.
/// Allows sending and receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcBidiChannel {
    label_id: LabelId,
    aqc_id: BidiChannelId,
    conn: s2n::Connection,
    identities: Vec<PskIdentity>,
    keys: ChannelKeys,
}

impl AqcBidiChannel {
    /// Create a new bidirectional channel with the given id and conection handle.
    pub(super) fn new<I>(
        label_id: LabelId,
        aqc_id: BidiChannelId,
        conn: s2n::Connection,
        identities: I,
        keys: ChannelKeys,
    ) -> Self
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        Self {
            label_id,
            aqc_id,
            conn,
            identities: identities.into_iter().collect(),
            keys,
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
            Ok(Some(stream)) => Ok(AqcPeerStream::new(stream)),
            Ok(None) => {
                // Connection closed by peer, no more streams will be accepted.
                Err(AqcError::ConnectionClosed)
            }
            Err(e) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                if let s2n_quic::connection::Error::Transport { code, .. } = e {
                    if code.as_u64() == ConnectionCloseError::ChannelClosed as u64 {
                        let _ = self.close().await;
                    }
                }
                Err(AqcError::ConnectionError(e))
            }
        }
    }

    /// Receive a stream if one is available. If there is no stream available,
    /// return Empty. If the channel is closed, return Disconnected. If disconnected
    /// is returned no streams will be available until a new channel is created.
    pub fn try_receive_stream(&mut self) -> Result<AqcPeerStream, TryReceiveError> {
        let mut cx = Context::from_waker(Waker::noop());

        match self.conn.poll_accept(&mut cx) {
            Poll::Ready(Ok(Some(stream))) => Ok(AqcPeerStream::new(stream)),
            Poll::Ready(Ok(None)) => {
                // Connection closed by peer, no more streams will be accepted.
                Err(TryReceiveError::Error(AqcError::ConnectionClosed))
            }
            Poll::Ready(Err(e)) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                if let s2n_quic::connection::Error::Transport { code, .. } = e {
                    if code.as_u64() == ConnectionCloseError::ChannelClosed as u64 {
                        let _ = futures_lite::future::block_on(self.close());
                    }
                }
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
        Ok(AqcSendStream(send))
    }

    /// Creates a new bidirectional stream for the channel.
    pub async fn create_bidi_stream(&mut self) -> Result<AqcBidiStream, AqcError> {
        let bidi = self.conn.open_bidirectional_stream().await?;
        Ok(AqcBidiStream(bidi))
    }

    /// Close the channel if it's open. If the channel is already closed, do nothing.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        debug!("closing aqc bidi channel");
        const ERROR_CODE: u32 = ConnectionCloseError::ChannelClosed as u32;
        self.conn.close(ERROR_CODE.into());
        self.keys.zeroize_psks(&self.identities);

        Ok(())
    }
}

impl Drop for AqcBidiChannel {
    fn drop(&mut self) {
        debug!("dropping aqc bidi channel");
        let _ = futures_lite::future::block_on(self.close());
    }
}

/// Used to send and receive data with a peer.
// TODO: implement `Drop`
#[derive(Debug)]
pub struct AqcBidiStream(s2n::BidirectionalStream);

impl AqcBidiStream {
    /// Split a bidi stream into send and receive halves.
    pub fn split(self) -> (AqcSendStream, AqcReceiveStream) {
        let (recv, send) = self.0.split();
        (AqcSendStream(send), AqcReceiveStream(recv))
    }

    /// Send data to the given stream.
    pub async fn send(&mut self, data: Bytes) -> Result<(), AqcError> {
        debug!("sending aqc data");
        self.0.send(data).await?;
        debug!("sent aqc data");
        Ok(())
    }

    /// Close the stream.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        debug!("closing aqc bidi stream");
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
        debug!("receiving aqc data");
        let data = self.0.receive().await?;
        debug!(?data, "received aqc data");
        Ok(data)
    }

    /// Receive the next available data from a stream.
    ///
    /// This method will return immediately with an error if there is no data available.
    /// The errors are:
    /// - Empty: No data available.
    /// - Closed: The stream is closed.
    pub fn try_receive(&mut self) -> Result<Bytes, TryReceiveError> {
        let mut cx = Context::from_waker(Waker::noop());
        match self.0.poll_receive(&mut cx) {
            Poll::Ready(Ok(Some(chunk))) => Ok(chunk),
            Poll::Ready(Ok(None)) => Err(TryReceiveError::Closed),
            Poll::Ready(Err(_e)) => Err(TryReceiveError::Closed),
            Poll::Pending => Err(TryReceiveError::Empty),
        }
    }
}

/// Used to receive data from a peer.
#[derive(Debug)]
pub struct AqcReceiveStream(s2n::ReceiveStream);

impl AqcReceiveStream {
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
        let mut cx = Context::from_waker(Waker::noop());
        match self.0.poll_receive(&mut cx) {
            Poll::Ready(Ok(Some(chunk))) => Ok(chunk),
            Poll::Ready(Ok(None)) => Err(TryReceiveError::Closed),
            Poll::Ready(Err(_e)) => Err(TryReceiveError::Closed),
            Poll::Pending => Err(TryReceiveError::Empty),
        }
    }

    /// Notify peer to stop sending to receive stream.
    pub fn close(&mut self) {
        debug!("closing aqc receive stream");
        const ERROR_CODE: u32 = 0;
        let _ = self.0.stop_sending(ERROR_CODE.into());
    }
}

impl Drop for AqcReceiveStream {
    fn drop(&mut self) {
        debug!("dropping aqc receive stream");
        self.close();
    }
}

/// Used to send data to a peer.
#[derive(Debug)]
pub struct AqcSendStream(s2n::SendStream);

impl AqcSendStream {
    /// Send data to the given stream.
    pub async fn send(&mut self, data: Bytes) -> Result<(), AqcError> {
        self.0.send(data).await?;
        Ok(())
    }
    /// Close the stream.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        debug!("closing aqc send stream");
        self.0.close().await?;
        Ok(())
    }
}

impl Drop for AqcSendStream {
    fn drop(&mut self) {
        debug!("dropping aqc send stream");
        let _ = futures_lite::future::block_on(self.close());
    }
}

/// A stream accepted from a peer.
#[derive(Debug)]
pub enum AqcPeerStream {
    /// A bidirectional stream.
    Bidi(AqcBidiStream),
    /// A receive-only stream.
    Receive(AqcReceiveStream),
}

impl AqcPeerStream {
    fn new(stream: s2n_quic::stream::PeerStream) -> Self {
        match stream {
            s2n::PeerStream::Bidirectional(stream) => Self::Bidi(AqcBidiStream(stream)),
            s2n::PeerStream::Receive(recv) => Self::Receive(AqcReceiveStream(recv)),
        }
    }

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

    /// Receive the next available data from a stream. If the stream has
    /// been closed, return None.
    ///
    /// This method will block until data is available to return.
    /// The data is not guaranteed to be complete, and may need to be called
    /// multiple times to receive all data from a message.
    pub async fn receive(&mut self) -> Result<Option<Bytes>, AqcError> {
        match self {
            AqcPeerStream::Bidi(s) => s.receive().await,
            AqcPeerStream::Receive(s) => s.receive().await,
        }
    }

    /// Receive the next available data from a stream.
    ///
    /// This method will return immediately with an error if there is no data available.
    /// The errors are:
    /// - Empty: No data available.
    /// - Closed: The stream is closed.
    pub fn try_receive(&mut self) -> Result<Bytes, TryReceiveError> {
        match self {
            AqcPeerStream::Bidi(s) => s.try_receive(),
            AqcPeerStream::Receive(s) => s.try_receive(),
        }
    }
}
