//! This module contains all generic syncer transport traits, as well as any transport-specific syncer implementations.

pub(crate) mod quic;

pub(crate) trait SyncStream: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn peer(&self) -> super::SyncPeer;

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    async fn receive(&mut self, buffer: &mut Vec<u8>) -> Result<(), Self::Error>;
    async fn finish(&mut self) -> Result<(), Self::Error>;
}

pub(crate) trait SyncTransport: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    type Stream: SyncStream<Error = Self::Error>;

    async fn connect(&self, peer: super::SyncPeer) -> Result<Self::Stream, Self::Error>;
}

pub(crate) trait SyncListener: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    type Stream: SyncStream<Error = Self::Error>;

    fn local_addr(&self) -> super::Addr;

    async fn accept(&mut self) -> Option<Result<Self::Stream, Self::Error>>;
}
