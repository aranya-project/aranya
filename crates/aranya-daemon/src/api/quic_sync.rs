use std::{path::PathBuf, sync::Arc};

use crate::{keystore::LocalStore, sync::task::quic::PskStore, CE, KS};

/// Held by [`super::DaemonApiServer`] when the QUIC syncer is used
pub(crate) struct Data {
    pub(crate) psk_store: Arc<PskStore>,
    pub(crate) store: LocalStore<KS>,
    pub(crate) engine: CE,
    pub(crate) seed_id_path: PathBuf,
}

impl std::fmt::Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QUIC sync API Data")
            .field("seed_id_path", &self.seed_id_path)
            .finish_non_exhaustive()
    }
}
