use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::aqc::net::{self as aqc};

/// An AQC channel that can both send and receive data.
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

/// An AQC channel that can only send data.
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

/// An AQC channel that can only receive data.
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

/// Container for an AQC Channel variant.
///
/// This needs to be destructured before it can be used, since C doesn't have
/// dataful enums.
pub struct AqcChannel {
    pub(crate) inner: aqc::AqcReceiveChannelType,
}

impl Typed for AqcChannel {
    const TYPE_ID: TypeId = TypeId::new(0x7A1D7BE9);
}

impl AqcChannel {
    pub fn new(channel: aqc::AqcReceiveChannelType) -> Self {
        Self { inner: channel }
    }
}

/// The sender end of an AQC stream.
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

/// The receiver end of an AQC stream.
pub struct AqcReceiveStream {
    pub(crate) inner: aqc::AqcReceiveStream,
    pub(crate) data: Option<bytes::Bytes>,
}

impl Typed for AqcReceiveStream {
    const TYPE_ID: TypeId = TypeId::new(0xB4D31DA6);
}

impl AqcReceiveStream {
    pub fn new(channel: aqc::AqcReceiveStream) -> Self {
        Self {
            inner: channel,
            data: None,
        }
    }
}
