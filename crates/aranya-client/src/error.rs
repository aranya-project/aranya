use aranya_crypto::apq::Version as AqcVersion;

/// Possible errors that could happen in the Aranya client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Unable to connect to the daemon.
    #[error("Unable to connect to the daemon: {0}")]
    Connecting(#[source] std::io::Error),

    /// Unable to communicate with the daemon.
    #[error("Unable to communicate with the daemon: {0}")]
    Rpc(#[from] tarpc::client::RpcError),

    /// The daemon returned an error.
    #[error("Daemon reported error: {0}")]
    Daemon(#[from] aranya_daemon_api::Error),

    /// A configuration error happened.
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// An Aranya QUIC Channel error happened.
    #[error("QUIC Channel error: {0}")]
    Aqc(#[from] AqcError),

    /// An unexpected internal error happened.
    #[error("Unexpected internal error: {0}")]
    Bug(#[from] buggy::Bug),
}

/// Possible errors that could happen when creating configuration info.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// An invalid argument was provided.
    #[error("Invalid argument `{arg}`: {reason}")]
    InvalidArg {
        arg: &'static str,
        reason: &'static str,
    },
}

/// Possible errors that could happen when using Aranya QUIC Channels.
#[derive(Debug, thiserror::Error)]
pub enum AqcError {
    #[error("unable to create channel")]
    ChannelCreation(aranya_aqc_util::Error),

    #[error("unable to parse encap")]
    Encap(anyhow::Error),

    // Connection-related errors
    /// Unable to bind a network addresss.
    #[error("unable to bind address: {0}")]
    Bind(std::io::Error),

    /// DNS lookup failed.
    #[error("DNS lookup failed: {0}")]
    DnsLookup(std::io::Error),

    /// Local address failure.
    #[error("unable to get local address: {0}")]
    RouterAddr(std::io::Error),

    /// Unable to parse shm path.
    #[error("unable to parse shared memory path: {0}")]
    ShmPathParse(aranya_fast_channels::shm::InvalidPathError),

    /// Unable to open the shm read state.
    #[error("unable to open shared memory `ReadState`: {0}")]
    ShmReadState(anyhow::Error),

    /// Unable to accept a QUIC stream.
    #[error("unable to accept to QUIC stream: {0}")]
    StreamAccept(std::io::Error),

    /// Unable to create a QUIC stream.
    #[error("unable to connect to QUIC stream: {0}")]
    StreamConnect(std::io::Error),

    /// Unable to read from QUIC stream.
    #[error("unable to read from QUIC stream: {0}")]
    StreamRead(std::io::Error),

    /// Unable to write to QUIC stream.
    #[error("unable to write to QUIC stream: {0}")]
    StreamWrite(std::io::Error),

    /// Unable to shutdown QUIC stream.
    #[error("unable to shutdown QUIC stream: {0}")]
    StreamShutdown(std::io::Error),

    /// Unable to get the remote peer's address.
    #[error("unable to get remote peer's address: {0}")]
    StreamPeerAddr(std::io::Error),

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

    // General errors
    /// Some other error.
    #[error("{0}")]
    Other(#[from] anyhow::Error),

    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] buggy::Bug),
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
