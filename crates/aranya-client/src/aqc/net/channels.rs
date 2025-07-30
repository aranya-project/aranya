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
    /// The QUIC connection has been closed without any error.
    ConnectionClosed,
    /// The AQC channel has been closed by the peer when closing the QUIC connection.
    ChannelClosed,
}

/// AQC channel Keys.
///
/// Each AQC channel will have a unique set of PSK identities and keys.
/// This structure provides access to a copy of client and server keys.
/// It enables the channel PSKs to easily be zeroized when an AQC channel is deleted.
#[derive(Debug, Clone)]
pub struct ChannelKeys {
    identities: Arc<Vec<PskIdentity>>,
    client_keys: Arc<ClientPresharedKeys>,
    server_keys: Arc<ServerPresharedKeys>,
}

impl ChannelKeys {
    /// Create a new set of AQC channel keys.
    pub(crate) fn new(
        identities: Vec<PskIdentity>,
        client_keys: Arc<ClientPresharedKeys>,
        server_keys: Arc<ServerPresharedKeys>,
    ) -> Self {
        Self {
            identities: Arc::new(identities),
            client_keys,
            server_keys,
        }
    }

    /// Zeroize the PSKs.
    pub fn zeroize(&self) {
        self.client_keys.zeroize_psks(&self.identities);
        self.server_keys.zeroize_psks(&self.identities);
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
        keys: ChannelKeys,
    ) -> Self {
        match channel_id {
            AqcChannelId::Bidi(id) => {
                // Once we accept a valid connection, let's turn it into an AQC Channel that we can
                // then open an arbitrary number of streams on.
                let channel = AqcBidiChannel::new(label_id, id, conn, keys);
                AqcPeerChannel::Bidi(channel)
            }
            AqcChannelId::Uni(id) => {
                // Once we accept a valid connection, let's turn it into an AQC Channel that we can
                // then open an arbitrary number of streams on.
                let receiver = AqcReceiveChannel::new(label_id, id, conn, keys);
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
    keys: ChannelKeys,
}

impl AqcSendChannel {
    /// Create a new channel with the given id and connection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub(super) fn new(
        label_id: LabelId,
        id: UniChannelId,
        handle: s2n::Handle,
        keys: ChannelKeys,
    ) -> Self {
        Self {
            label_id,
            id,
            handle,
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
        match self.handle.open_send_stream().await {
            Ok(send) => Ok(AqcSendStream::new(send, self.keys.clone())),
            Err(e) => {
                if conn_channel_closed(e) {
                    let _ = self.close().await;
                }
                Err(AqcError::ConnectionError(e))
            }
        }
    }

    /// Close the channel if it's open. If the channel is already closed, do nothing.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        debug!("closing aqc send channel");
        const ERROR_CODE: u32 = ConnectionCloseError::ChannelClosed as u32;
        self.handle.close(ERROR_CODE.into());
        self.keys.zeroize();

        Ok(())
    }
}

/// The receive end of a unidirectional channel.
/// Allows receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcReceiveChannel {
    label_id: LabelId,
    aqc_id: UniChannelId,
    conn: s2n::Connection,
    keys: ChannelKeys,
}

impl AqcReceiveChannel {
    /// Create a new channel with the given connection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub(super) fn new(
        label_id: LabelId,
        aqc_id: UniChannelId,
        conn: s2n::Connection,
        keys: ChannelKeys,
    ) -> Self {
        Self {
            label_id,
            aqc_id,
            conn,
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
            Ok(Some(stream)) => Ok(AqcReceiveStream::new(stream, self.keys.clone())),
            Ok(None) => {
                // Connection closed by peer, no more streams will be accepted.
                Err(AqcError::ConnectionClosed)
            }
            Err(e) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                if conn_channel_closed(e) {
                    let _ = self.close().await;
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
            Poll::Ready(Ok(Some(stream))) => Ok(AqcReceiveStream::new(stream, self.keys.clone())),
            Poll::Ready(Ok(None)) => {
                // Connection closed by peer, no more streams will be accepted.
                Err(TryReceiveError::Error(AqcError::ConnectionClosed))
            }
            Poll::Ready(Err(e)) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                if conn_channel_closed(e) {
                    let _ = futures_lite::future::block_on(self.close());
                }
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
        self.keys.zeroize();

        Ok(())
    }
}

/// A unique channel between two peers.
/// Allows sending and receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcBidiChannel {
    label_id: LabelId,
    aqc_id: BidiChannelId,
    conn: s2n::Connection,
    keys: ChannelKeys,
}

impl AqcBidiChannel {
    /// Create a new bidirectional channel with the given id and conection handle.
    pub(super) fn new(
        label_id: LabelId,
        aqc_id: BidiChannelId,
        conn: s2n::Connection,
        keys: ChannelKeys,
    ) -> Self {
        Self {
            label_id,
            aqc_id,
            conn,
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
            Ok(Some(stream)) => Ok(AqcPeerStream::new(stream, self.keys.clone())),
            Ok(None) => {
                // Connection closed by peer, no more streams will be accepted.
                Err(AqcError::ConnectionClosed)
            }
            Err(e) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                if conn_channel_closed(e) {
                    let _ = self.close().await;
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
            Poll::Ready(Ok(Some(stream))) => Ok(AqcPeerStream::new(stream, self.keys.clone())),
            Poll::Ready(Ok(None)) => {
                // Connection closed by peer, no more streams will be accepted.
                Err(TryReceiveError::Error(AqcError::ConnectionClosed))
            }
            Poll::Ready(Err(e)) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                if conn_channel_closed(e) {
                    let _ = futures_lite::future::block_on(self.close());
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
        match self.conn.open_send_stream().await {
            Ok(send) => Ok(AqcSendStream::new(send, self.keys.clone())),
            Err(e) => {
                if conn_channel_closed(e) {
                    let _ = self.close().await;
                }
                Err(AqcError::ConnectionError(e))
            }
        }
    }

    /// Creates a new bidirectional stream for the channel.
    pub async fn create_bidi_stream(&mut self) -> Result<AqcBidiStream, AqcError> {
        match self.conn.open_bidirectional_stream().await {
            Ok(bidi) => Ok(AqcBidiStream::new(bidi, self.keys.clone())),
            Err(e) => {
                if conn_channel_closed(e) {
                    let _ = self.close().await;
                }
                Err(AqcError::ConnectionError(e))
            }
        }
    }

    /// Close the channel if it's open. If the channel is already closed, do nothing.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        debug!("closing aqc bidi channel");
        const ERROR_CODE: u32 = ConnectionCloseError::ChannelClosed as u32;
        self.conn.close(ERROR_CODE.into());
        self.keys.zeroize();

        Ok(())
    }
}

/// Used to send and receive data with a peer.
#[derive(Debug)]
pub struct AqcBidiStream {
    stream: s2n::BidirectionalStream,
    keys: ChannelKeys,
}

impl AqcBidiStream {
    /// Creates a new AQC bidirectional stream.
    pub fn new(stream: s2n::BidirectionalStream, keys: ChannelKeys) -> Self {
        Self { stream, keys }
    }

    /// Split a bidi stream into send and receive halves.
    pub fn split(self) -> (AqcSendStream, AqcReceiveStream) {
        let (recv, send) = self.stream.split();
        (
            AqcSendStream::new(send, self.keys.clone()),
            AqcReceiveStream::new(recv, self.keys.clone()),
        )
    }

    /// Send data to the given stream.
    pub async fn send(&mut self, data: Bytes) -> Result<(), AqcError> {
        if let Err(e) = self.stream.send(data).await {
            let _ = self.close().await;
            if channel_closed(e) {
                self.keys.zeroize();
            }
            return Err(AqcError::StreamError(e));
        }
        Ok(())
    }

    /// Receive the next available data from a stream. If the stream has
    /// been closed, return None.
    ///
    /// This method will block until data is available to return.
    /// The data is not guaranteed to be complete, and may need to be called
    /// multiple times to receive all data from a message.
    pub async fn receive(&mut self) -> Result<Option<Bytes>, AqcError> {
        match self.stream.receive().await {
            Ok(data) => Ok(data),
            Err(e) => {
                let _ = self.close().await;
                if channel_closed(e) {
                    self.keys.zeroize();
                }
                Err(AqcError::StreamError(e))
            }
        }
    }

    /// Receive the next available data from a stream.
    ///
    /// This method will return immediately with an error if there is no data available.
    /// The errors are:
    /// - Empty: No data available.
    /// - Closed: The stream is closed.
    pub fn try_receive(&mut self) -> Result<Bytes, TryReceiveError> {
        let mut cx = Context::from_waker(Waker::noop());
        match self.stream.poll_receive(&mut cx) {
            Poll::Ready(Ok(Some(chunk))) => Ok(chunk),
            Poll::Ready(Ok(None)) => Err(TryReceiveError::StreamClosed),
            Poll::Ready(Err(e)) => {
                if channel_closed(e) {
                    let _ = futures_lite::future::block_on(self.close());
                    self.keys.zeroize();
                }
                Err(TryReceiveError::StreamClosed)
            }
            Poll::Pending => Err(TryReceiveError::Empty),
        }
    }

    /// Close the stream.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        debug!("closing aqc bidi stream");
        if let Err(e) = self.stream.close().await {
            if channel_closed(e) {
                self.keys.zeroize();
            }
            return Err(AqcError::StreamError(e));
        }
        Ok(())
    }
}

/// Used to receive data from a peer.
#[derive(Debug)]
pub struct AqcReceiveStream {
    stream: s2n::ReceiveStream,
    keys: ChannelKeys,
}

impl AqcReceiveStream {
    /// Creates a new AQC receive stream.
    pub fn new(stream: s2n::ReceiveStream, keys: ChannelKeys) -> Self {
        Self { stream, keys }
    }

    /// Receive the next available data from a stream. If the stream has
    /// been closed, return None.
    ///
    /// This method will block until data is available to return.
    /// The data is not guaranteed to be complete, and may need to be called
    /// multiple times to receive all data from a message.
    pub async fn receive(&mut self) -> Result<Option<Bytes>, AqcError> {
        match self.stream.receive().await {
            Ok(bytes) => Ok(bytes),
            Err(e) => {
                self.close();
                if channel_closed(e) {
                    self.keys.zeroize();
                }
                Err(AqcError::StreamError(e))
            }
        }
    }

    /// Receive the next available data from a stream.
    ///
    /// This method will return immediately with an error if there is no data available.
    /// The errors are:
    /// - Empty: No data available.
    /// - Closed: The stream is closed.
    pub fn try_receive(&mut self) -> Result<Bytes, TryReceiveError> {
        let mut cx = Context::from_waker(Waker::noop());
        match self.stream.poll_receive(&mut cx) {
            Poll::Ready(Ok(Some(chunk))) => Ok(chunk),
            Poll::Ready(Ok(None)) => Err(TryReceiveError::StreamClosed),
            Poll::Ready(Err(e)) => {
                self.close();
                if channel_closed(e) {
                    self.keys.zeroize();
                }
                Err(TryReceiveError::StreamClosed)
            }
            Poll::Pending => Err(TryReceiveError::Empty),
        }
    }

    /// Notify peer to stop sending to receive stream.
    pub fn close(&mut self) {
        debug!("closing aqc receive stream");
        const ERROR_CODE: u32 = ConnectionCloseError::ConnectionClosed as u32;
        let _ = self.stream.stop_sending(ERROR_CODE.into());
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
pub struct AqcSendStream {
    stream: s2n::SendStream,
    keys: ChannelKeys,
}

impl AqcSendStream {
    /// Creates a new AQC send stream.
    pub fn new(stream: s2n::SendStream, keys: ChannelKeys) -> Self {
        Self { stream, keys }
    }

    /// Send data to the given stream.
    pub async fn send(&mut self, data: Bytes) -> Result<(), AqcError> {
        if let Err(e) = self.stream.send(data).await {
            let _ = self.close().await;
            if channel_closed(e) {
                self.keys.zeroize();
            }
            return Err(AqcError::StreamError(e));
        }
        Ok(())
    }
    /// Close the stream.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        debug!("closing aqc send stream");
        if let Err(e) = self.stream.close().await {
            if channel_closed(e) {
                self.keys.zeroize();
            }
            return Err(AqcError::StreamError(e));
        }
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
    fn new(stream: s2n_quic::stream::PeerStream, keys: ChannelKeys) -> Self {
        match stream {
            s2n::PeerStream::Bidirectional(stream) => Self::Bidi(AqcBidiStream::new(stream, keys)),
            s2n::PeerStream::Receive(recv) => Self::Receive(AqcReceiveStream::new(recv, keys)),
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

/// Returns true if the connection error indicates the AQC channel was closed.
fn conn_channel_closed(e: s2n_quic::connection::Error) -> bool {
    if let s2n_quic::connection::Error::Transport { code, .. } = e {
        if code.as_u64() == ConnectionCloseError::ChannelClosed as u64 {
            return true;
        }
    }
    false
}

// Returns true if the stream error indicates the AQC channel was closed.
fn channel_closed(e: s2n_quic::stream::Error) -> bool {
    if let s2n_quic::stream::Error::ConnectionError {
        error: s2n_quic::connection::Error::Transport { code, .. },
        ..
    } = e
    {
        if code.as_u64() == ConnectionCloseError::ChannelClosed as u64 {
            return true;
        }
    }
    false
}
