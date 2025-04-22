use std::io;

use aranya_daemon_api as api;
#[cfg(feature = "afc")]
use aranya_daemon_api::AfcId;
#[cfg(feature = "afc")]
use aranya_fast_channels::Version;
use tarpc::client::RpcError;

pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Possible errors that could happen in the Aranya client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Unable to communicate with the daemon.
    #[error("IPC error: {0}")]
    Ipc(#[from] IpcError),

    /// The daemon returned an error.
    #[error("daemon error: {0}")]
    Aranya(#[from] AranyaError),

    /// A configuration error happened.
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    /// An Aranya Fast Channel error happened.
    #[error("AFC error: {0}")]
    #[cfg(feature = "afc")]
    Afc(#[from] AfcError),

    /// An Aranya QUIC Channel error happened.
    #[error("AQC error: {0}")]
    Aqc(#[from] AqcError),

    /// An unexpected internal error happened.
    #[error("unexpected internal error: {0}")]
    Bug(#[from] buggy::Bug),
}

/// An Aranya error.
#[derive(Debug, thiserror::Error)]
#[error("{err}")]
pub struct AranyaError {
    #[from]
    err: api::Error,
}

pub(crate) fn aranya_error(err: api::Error) -> Error {
    Error::Aranya(err.into())
}

/// Possible errors that could happen when creating configuration info.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// An invalid argument was provided.
    #[error("{0}")]
    InvalidArg(#[from] InvalidArg),
}

/// An invalid argument.
#[derive(Debug, thiserror::Error)]
#[error("invalid argument `{arg}`: {reason}")]
pub struct InvalidArg {
    arg: &'static str,
    reason: &'static str,
}

impl InvalidArg {
    pub(crate) const fn new(arg: &'static str, reason: &'static str) -> Self {
        Self { arg, reason }
    }
}

/// An IPC error.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct IpcError(#[from] pub(crate) IpcRepr);

impl IpcError {
    pub(crate) fn new<E>(err: E) -> Self
    where
        E: Into<IpcRepr>,
    {
        Self(err.into())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) enum IpcRepr {
    InvalidArg(#[from] InvalidArg),
    Io(#[from] io::Error),
    Tarpc(#[from] RpcError),
}

/// Possible errors that could happen when using Aranya Fast Channels.
#[derive(Debug, thiserror::Error)]
#[cfg(feature = "afc")]
#[non_exhaustive]
pub enum AfcError {
    // Connection-related errors
    /// Unable to bind a network addresss.
    #[error("unable to bind address: {0}")]
    Bind(io::Error),

    /// DNS lookup failed.
    #[error("DNS lookup failed: {0}")]
    DnsLookup(io::Error),

    /// Local address failure.
    #[error("unable to get local address: {0}")]
    RouterAddr(io::Error),

    /// Unable to parse shm path.
    #[error("unable to parse shared memory path: {0}")]
    ShmPathParse(aranya_fast_channels::shm::InvalidPathError),

    /// Unable to open the shm read state.
    #[error("unable to open shared memory `ReadState`: {0}")]
    ShmReadState(anyhow::Error),

    /// Unable to accept a TCP stream.
    #[error("unable to accept to TCP stream: {0}")]
    StreamAccept(io::Error),

    /// Unable to create a TCP stream.
    #[error("unable to connect to TCP stream: {0}")]
    StreamConnect(io::Error),

    /// Unable to read from TCP stream.
    #[error("unable to read from TCP stream: {0}")]
    StreamRead(io::Error),

    /// Unable to write to TCP stream.
    #[error("unable to write to TCP stream: {0}")]
    StreamWrite(io::Error),

    /// Unable to shutdown TCP stream.
    #[error("unable to shutdown TCP stream: {0}")]
    StreamShutdown(io::Error),

    /// Unable to get the remote peer's address.
    #[error("unable to get remote peer's address: {0}")]
    StreamPeerAddr(io::Error),

    /// The stream was not found.
    #[error("stream not found: {0}")]
    StreamNotFound(net::SocketAddr),

    // Protocol-related errors
    /// Invalid AFC header.
    #[error("invalid AFC header: {0}")]
    InvalidHeader(#[from] aranya_fast_channels::HeaderError),

    /// Invalid AFC magic.
    #[error("invalid magic: {0}")]
    InvalidMagic(u32),

    /// Invalid AFC message.
    #[error("invalid message: {0}")]
    InvalidMsg(#[from] aranya_fast_channels::ParseError),

    /// AFC message was replayed.
    #[error("AFC message was replayed: {0}")]
    MsgReplayed(String),

    /// The message length prefix was larger than the maximum
    /// allowed size.
    #[error("message too large: {got} > {max}")]
    MsgTooLarge { got: usize, max: usize },

    /// Payload is too small to be ciphertext.
    #[error("payload is too small to be ciphertext")]
    PayloadTooSmall,

    /// AFC message decryption failure.
    #[error("decryption failure: {0}")]
    Decryption(aranya_fast_channels::Error),

    /// AFC message encryption failure.
    #[error("encryption failure: {0}")]
    Encryption(aranya_fast_channels::Error),

    /// Serde serialization/deserialization error.
    #[error("serialization/deserialization error: {0}")]
    Serde(postcard::Error),

    /// AFC version mismatch.
    #[error("AFC version mismatch: got {actual:?}, expected {expected:?}")]
    VersionMismatch { expected: Version, actual: Version },

    // General errors
    /// The channel was not found.
    #[error("channel not found: {0}")]
    ChannelNotFound(AfcId),

    /// The 64-bit sequence number overflowed and the end of the channel was
    /// reached. A new channel must be created.
    ///
    /// # Note
    ///
    /// This likely indicates that the peer manually set a very high sequence
    /// number.
    #[error("end of channel reached")]
    EndOfChannel,

    /// Some other error.
    #[error("{0}")]
    Other(#[from] anyhow::Error),

    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] buggy::Bug),
}

/// Possible errors that could happen when using Aranya QUIC Channels.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AqcError {
    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] buggy::Bug),

    /// Some other error.
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
