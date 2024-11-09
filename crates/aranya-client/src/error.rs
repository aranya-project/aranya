/// Errors that could occur in the Aranya client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Could not connect to the daemon.
    #[error("could not connect to daemon: {0}")]
    Connecting(#[source] std::io::Error),

    /// Aranya Fast Channels router error.
    #[error("afc router error: {0}")]
    AfcRouter(#[from] crate::afc::AfcRouterError),

    /// Could not send request to daemon.
    #[error("could not send request to daemon: {0}")]
    Rpc(#[from] tarpc::client::RpcError),

    /// Daemon reported error.
    #[error("daemon reported error: {0}")]
    Daemon(#[from] aranya_daemon_api::Error),

    /// Aranya Fast Channels memory error.
    #[error("AFC shared memory error: {0}")]
    AfcShm(#[from] aranya_fast_channels::shm::Error),

    /// Aranya Fast Channels error.
    #[error("AFC error: {0}")]
    Afc(#[from] aranya_fast_channels::Error),

    /// Unexpected internal error.
    #[error("Unexpected internal error: {0}")]
    Bug(#[from] aranya_buggy::Bug),
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
