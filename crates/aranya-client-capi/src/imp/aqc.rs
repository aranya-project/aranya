use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::aqc_net::{self as aqc};

pub struct AqcBidiChannel {
    inner: aqc::AqcBidirectionalChannel,
}

impl Typed for AqcBidiChannel {
    const TYPE_ID: TypeId = TypeId::new(0x7B446A10);
}

impl AqcBidiChannel {
    pub fn new(channel: aqc::AqcBidirectionalChannel) -> Self {
        Self { inner: channel }
    }
}

/*
TODO(nikki): implement uni channels
pub struct AqcUniChannel {
    inner: aqc::AqcUnidirectionalChannel,
}

impl Typed for AqcUniChannel {
    const TYPE_ID: TypeId = TypeId::new(0xD3DE3627);
}

impl AqcUniChannel {
    pub fn new(channel: aqc::AqcUnidirectionalChannel) -> Self {
        Self { inner: channel }
    }
}
*/

pub struct AqcChannelType {
    inner: aqc::AqcChannelType,
}

impl Typed for AqcChannelType {
    const TYPE_ID: TypeId = TypeId::new(0x7A1D7BE9);
}

impl AqcChannelType {
    pub fn new(channel: aqc::AqcChannelType) -> Self {
        Self { inner: channel }
    }
}
