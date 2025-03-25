use aranya_capi_core::safe::{TypeId, Typed};

use super::Duration;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[aranya_capi_core::opaque(size = 16, align = 8)]
pub struct SyncPeerConfig {
    interval: Duration,
    sync_now: bool,
}

impl Typed for SyncPeerConfig {
    const TYPE_ID: TypeId = TypeId::new(0x2049e682);
}

impl From<SyncPeerConfig> for aranya_client::SyncPeerConfig {
    fn from(value: SyncPeerConfig) -> Self {
        Self::builder()
            .interval(value.interval.into())
            .sync_now(value.sync_now)
            .build()
    }
}

impl From<&SyncPeerConfig> for aranya_client::SyncPeerConfig {
    fn from(value: &SyncPeerConfig) -> Self {
        (*value).into()
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[aranya_capi_core::opaque(size = 16, align = 8)]
pub struct SyncPeerConfigBuilder {
    interval: Duration,
    sync_now: bool,
}

impl Typed for SyncPeerConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x2049e683);
}

impl Default for SyncPeerConfigBuilder {
    fn default() -> Self {
        Self {
            interval: Duration {
                nanos: 100 * super::ARANYA_DURATION_MILLISECONDS,
            },
            sync_now: true,
        }
    }
}
