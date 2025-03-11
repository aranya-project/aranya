/// Errors that could occur in the Aranya client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Unable to connect to the daemon.
    #[error("Unable to connect to the daemon: {0}")]
    Connecting(#[source] std::io::Error),

    /// Unable to communicate with the daemon.
    #[error("Unable to communicate with the daemon: {0}")]
    Rpc(#[from] tarpc::client::RpcError),

    /// An error occurred in the daemon.
    #[error("Daemon Reported Error: {0}")]
    Daemon(#[from] aranya_daemon_api::Error),

    /// An error occurred when using an Aranya Fast Channel.
    #[error("Fast Channel Error: {0}")]
    Afc(#[from] crate::afc::AfcError),

    /// Unexpected internal error.
    #[error("Unexpected internal error: {0}")]
    Bug(#[from] aranya_buggy::Bug),
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
