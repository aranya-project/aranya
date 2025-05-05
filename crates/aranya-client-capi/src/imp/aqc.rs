use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::aqc::net::{self as aqc};

// TODO(nikki): refactor this to add accessors and remove pub(crate) on inners.

pub struct AqcBidiChannel {
    pub(crate) inner: aqc::AqcBidirectionalChannel,
}

impl Typed for AqcBidiChannel {
    const TYPE_ID: TypeId = TypeId::new(0x7B446A10);
}

impl AqcBidiChannel {
    pub fn new(channel: aqc::AqcBidirectionalChannel) -> Self {
        Self { inner: channel }
    }
}

pub struct AqcSenderChannel {
    pub(crate) inner: aqc::AqcSenderChannel,
}

impl Typed for AqcSenderChannel {
    const TYPE_ID: TypeId = TypeId::new(0x302D3843);
}

impl AqcSenderChannel {
    pub fn new(channel: aqc::AqcSenderChannel) -> Self {
        Self { inner: channel }
    }
}

pub struct AqcReceiverChannel {
    pub(crate) inner: aqc::AqcReceiverChannel,
}

impl Typed for AqcReceiverChannel {
    const TYPE_ID: TypeId = TypeId::new(0x62A97986);
}

impl AqcReceiverChannel {
    pub fn new(channel: aqc::AqcReceiverChannel) -> Self {
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
    pub(crate) inner: aqc::AqcChannelType,
}

impl Typed for AqcChannelType {
    const TYPE_ID: TypeId = TypeId::new(0x7A1D7BE9);
}

impl AqcChannelType {
    pub fn new(channel: aqc::AqcChannelType) -> Self {
        Self { inner: channel }
    }
}

pub struct AqcSendStream {
    pub(crate) inner: aqc::AqcSendStream,
}

impl Typed for AqcSendStream {
    const TYPE_ID: TypeId = TypeId::new(0x8C03E403);
}

impl AqcSendStream {
    pub fn new(channel: aqc::AqcSendStream) -> Self {
        Self { inner: channel }
    }
}

pub struct AqcReceiveStream {
    pub(crate) inner: aqc::AqcReceiveStream,
}

impl Typed for AqcReceiveStream {
    const TYPE_ID: TypeId = TypeId::new(0xB4D31DA6);
}

impl AqcReceiveStream {
    pub fn new(channel: aqc::AqcReceiveStream) -> Self {
        Self { inner: channel }
    }
}
