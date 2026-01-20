#![cfg(feature = "afc")]
#![cfg_attr(docsrs, doc(cfg(feature = "afc")))]

pub use aranya_fast_channels::{shm, LocalChannelId as AfcLocalChannelId};
use aranya_id::custom_id;
use serde::{Deserialize, Serialize};

use crate::{DeviceId, LabelId};

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

/// Information returned when creating an AFC send channel.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AfcSendChannelInfo {
    pub ctrl: AfcCtrl,
    pub local_channel_id: AfcLocalChannelId,
    pub channel_id: AfcChannelId,
}

/// Information returned when receiving an AFC receive channel.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AfcReceiveChannelInfo {
    pub local_channel_id: AfcLocalChannelId,
    pub channel_id: AfcChannelId,
    pub label_id: LabelId,
    pub peer_id: DeviceId,
}
