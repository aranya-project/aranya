#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not connect to daemon: {0}")]
    Connecting(#[source] std::io::Error),

    #[error("could not send request to daemon: {0}")]
    Rpc(#[from] tarpc::client::RpcError),

    #[error("daemon reported error: {0}")]
    Daemon(#[from] aranya_daemon_api::Error),

    #[error("AFC shared memory error: {0}")]
    AfcShm(#[from] aranya_fast_channels::shm::Error),

    #[error("AFC error: {0}")]
    Afc(#[from] aranya_fast_channels::Error),

    #[error("Unexpected internal error: {0}")]
    Bug(#[from] aranya_buggy::Bug),
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
