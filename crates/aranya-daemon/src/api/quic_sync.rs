use std::sync::Arc;

use crate::sync::task::quic::PskStore;

/// Held by [`super::DaemonApiServer`] when the QUIC syncer is used
#[derive(Debug)]
pub(crate) struct Data {
    pub(crate) psk_store: Arc<PskStore>,
}
