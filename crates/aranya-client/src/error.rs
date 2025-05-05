use std::io;

use aranya_daemon_api as api;
use tarpc::client::RpcError;

use crate::aqc::api::AqcVersion;

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

    /// An Aranya QUIC Channel error happened.
    #[error("AQC error: {0}")]
    Aqc(#[from] AqcError),

    /// An unexpected internal error happened.
    #[error("unexpected internal error: {0}")]
    Bug(#[from] buggy::Bug),

    /// Some other error occurred.
    #[error("{0}")]
    Other(#[from] OtherError),
}

/// Some other error occurred.
#[derive(Debug, thiserror::Error)]
#[error("{err}")]
pub struct OtherError {
    #[from]
    err: anyhow::Error,
}

pub(crate) fn other<E>(err: E) -> OtherError
where
    E: Into<anyhow::Error>,
{
    OtherError { err: err.into() }
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
    Other(#[from] anyhow::Error),
}

/// Possible errors that could happen when using Aranya QUIC Channels.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AqcError {
    #[error("unable to create channel")]
    ChannelCreation(aranya_aqc_util::Error),

    #[error("unable to parse encap")]
    Encap(anyhow::Error),

    /// The channel was not found.
    #[error("channel not found")]
    ChannelNotFound,

    /// Received an unexpected channel type.
    #[error("received unexpected channel type: {0}")]
    UnexpectedChannelType(String),

    // Connection-related errors
    /// Unable to bind a network addresss.
    #[error("unable to bind address: {0}")]
    Bind(io::Error),

    /// DNS lookup failed.
    #[error("DNS lookup failed: {0}")]
    DnsLookup(io::Error),

    /// Failed to resolve address.
    #[error("failed to resolve address: {0}")]
    AddrResolution(io::Error),

    /// Address not found.
    #[error("unable to parse address: {0}")]
    AddrParse(std::net::AddrParseError),

    /// Address not found.
    #[error("address not found: {0}")]
    AddrNotFound(String),

    /// TLS configuration error.
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    /// IO configuration error.
    #[error("IO configuration error: {0}")]
    IoConfig(String),

    /// Congestion controller configuration error.
    #[error("Congestion controller configuration error: {0}")]
    CongestionConfig(String),

    /// Server start error.
    #[error("Server start error: {0}")]
    ServerStart(String),

    /// Local address failure.
    #[error("unable to get local address: {0}")]
    RouterAddr(io::Error),

    /// Unable to parse shm path.
    #[error("unable to parse shared memory path: {0}")]
    ShmPathParse(aranya_fast_channels::shm::InvalidPathError),

    /// Unable to open the shm read state.
    #[error("unable to open shared memory `ReadState`: {0}")]
    ShmReadState(anyhow::Error),

    /// Unable to accept a QUIC stream.
    #[error("unable to accept to QUIC stream: {0}")]
    StreamAccept(io::Error),

    /// Unable to create a QUIC stream.
    #[error("unable to connect to QUIC stream: {0}")]
    StreamConnect(io::Error),

    /// Unable to read from QUIC stream.
    #[error("unable to read from QUIC stream: {0}")]
    StreamRead(io::Error),

    /// Unable to write to QUIC stream.
    #[error("unable to write to QUIC stream: {0}")]
    StreamWrite(io::Error),

    /// Unable to shutdown QUIC stream.
    #[error("unable to shutdown QUIC stream: {0}")]
    StreamShutdown(io::Error),

    /// Unable to get the remote peer's address.
    #[error("unable to get remote peer's address: {0}")]
    StreamPeerAddr(io::Error),

    /// The stream was not found.
    #[error("stream not found: {0}")]
    StreamNotFound(std::net::SocketAddr),

    /// The message length prefix was larger than the maximum
    /// allowed size.
    #[error("message too large: {got} > {max}")]
    MsgTooLarge { got: usize, max: usize },

    /// Payload is too small to be ciphertext.
    #[error("payload is too small to be ciphertext")]
    PayloadTooSmall,

    /// AQC message decryption failure.
    #[error("decryption failure: {0}")]
    Decryption(aranya_fast_channels::Error),

    /// AQC message encryption failure.
    #[error("encryption failure: {0}")]
    Encryption(aranya_fast_channels::Error),

    /// Serde serialization/deserialization error.
    #[error("serialization/deserialization error: {0}")]
    Serde(postcard::Error),

    /// AQC version mismatch.
    #[error("AQC version mismatch: got {actual:?}, expected {expected:?}")]
    VersionMismatch {
        expected: AqcVersion,
        actual: AqcVersion,
    },

    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] buggy::Bug),

    // General errors
    /// Some other error.
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
