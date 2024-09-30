#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not connect to daemon: {0}")]
    Connecting(#[source] std::io::Error),

    #[error("could not send request to daemon: {0}")]
    Rpc(#[from] tarpc::client::RpcError),

    #[error("daemon reported error: {0}")]
    Daemon(#[from] daemon_api::Error),

    #[error("APS shared memory error: {0}")]
    ApsShm(#[from] aps::shm::Error),

    #[error("APS error: {0}")]
    Aps(#[from] aps::Error),

    #[error("Unexpected internal error: {0}")]
    Bug(#[from] buggy::Bug),
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
