/// Errors that could occur in the Aranya client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// AFC error.
    #[error("AFC error: {0}")]
    Afc(#[from] crate::afc::AfcError),

    /// Unexpected internal error.
    #[error("Unexpected internal error: {0}")]
    Bug(#[from] buggy::Bug),

    /// Could not connect to the daemon.
    #[error("could not connect to daemon: {0}")]
    Connecting(#[source] std::io::Error),

    /// Daemon reported error.
    #[error("daemon reported error: {0}")]
    Daemon(#[from] aranya_daemon_api::Error),

    /// Could not send request to daemon.
    #[error("could not send request to daemon: {0}")]
    Rpc(#[from] tarpc::client::RpcError),
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
