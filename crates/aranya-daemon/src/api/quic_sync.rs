use tokio::sync::broadcast;

use super::Msg;
use crate::{keystore::LocalStore, CE, KS};

/// Held by [`super::DaemonApiServer`] when the QUIC syncer is used
pub(crate) struct Data {
    /// Channel for sending PSK updates
    pub(crate) psk_send: broadcast::Sender<Msg>,
    pub(crate) store: LocalStore<KS>,
    pub(crate) engine: CE,
}

impl std::fmt::Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QUIC sync API Data").finish_non_exhaustive()
    }
}
