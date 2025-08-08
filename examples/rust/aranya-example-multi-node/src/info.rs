//! Device info sent between peers in the example.

use aranya_daemon_api::DeviceId;
use serde::{Deserialize, Serialize};

/// Device info sent from a member to the operator so it can assign network identifiers.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub device_id: DeviceId,
}
