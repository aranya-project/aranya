#![cfg(feature = "afc")]
#![cfg_attr(docsrs, doc(cfg(feature = "afc")))]

pub use aranya_fast_channels::{shm, ChannelId as AfcLocalChannelId};
use aranya_id::custom_id;
use serde::{Deserialize, Serialize};

custom_id! {
    /// An globally unique AFC channel ID.
    pub struct AfcChannelId;
}

/// A serialized command for AFC.
pub type AfcCtrl = Box<[u8]>;

/// AFC shared-memory info.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AfcShmInfo {
    pub path: Box<shm::Path>,
    pub max_chans: usize,
}
