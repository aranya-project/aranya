//! This module contains all generic syncer transport traits, as well as any transport-specific
//! syncer implementations.

pub(crate) mod quic;

/// A reliable, ordered, bidirectional byte stream tied to a specific peer.
///
/// A single stream can be used for an entire sync conversation/exchange, dictated by the two peers'
/// [`SyncManager`]. The protocol currently only needs one round trip, but this may change as the sync
/// protocol evolves.
///
/// Abstracts over any reliable, ordered transport (QUIC, TCP, WebSocket, UDS, etc). Unreliable
/// protocols like raw UDP are not suitable without an additional reliability layer.
///
/// [`SyncManager`]: super::SyncManager
pub(crate) trait SyncStream: Send + Sync + 'static {
    /// The specific error type this stream uses.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns the unique `SyncPeer` this stream is connected to.
    fn peer(&self) -> super::SyncPeer;

    /// Sends a message to the peer.
    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    /// Receives a message from the peer, returning the number of bytes written.
    async fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error>;
    /// Signals that no more data will be sent on this stream.
    ///
    /// For transports that support half-close (e.g. QUIC, TCP), this notifies the remote peer that
    /// sending is complete. Transports without half-close can implement this as a no-op.
    async fn finish(&mut self) -> Result<(), Self::Error>;
}

/// Opens outbound connections to sync peers.
///
/// This is the client-side counterpart to [`SyncListener`]. The [`SyncManager`] calls [`connect`]
/// whenever it needs to initiate a sync exchange and handles the protocol; implementations only
/// need to yield connected streams.
///
/// [`SyncManager`]: super::SyncManager
/// [`connect`]: Self::connect
pub(crate) trait SyncTransport: Send + Sync + 'static {
    /// The specific error type this stream uses.
    type Error: std::error::Error + Send + Sync + 'static;
    /// The stream type returned from connecting to a peer.
    type Stream: SyncStream<Error = Self::Error>;

    /// Connect to a peer to send and receive data.
    async fn connect(&self, peer: super::SyncPeer) -> Result<Self::Stream, Self::Error>;
}

/// Accepts inbound connections from sync peers.
///
/// This is the server-side counterpart to [`SyncTransport`]. The [`SyncServer`] drives this
/// listener and handles the protocol; implementations only need to yield connected streams.
///
/// [`SyncServer`]: super::SyncServer
pub(crate) trait SyncListener: Send + Sync + 'static {
    /// The specific error type this stream uses.
    type Error: std::error::Error + Send + Sync + 'static;
    /// The stream type returned from accepting a connection.
    type Stream: SyncStream<Error = Self::Error>;

    /// The local address the listener/server is bound to.
    fn local_addr(&self) -> super::Addr;

    /// Accept a connection from a peer to send and receive data.
    async fn accept(&mut self) -> Option<Result<Self::Stream, Self::Error>>;
}
