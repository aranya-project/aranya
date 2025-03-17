/// Possible errors that could happen in the Aranya client.
#[derive(Debug, thiserror::Error)]
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

    /// An Aranya Fast Channel error happened.
    #[error("Fast Channel error: {0}")]
    Afc(#[from] crate::afc::AfcError),

    /// An unexpected internal error happened.
    #[error("Unexpected internal error: {0}")]
    Bug(#[from] buggy::Bug),
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
