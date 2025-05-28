use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::aqc;

/// An AQC channel that can both send and receive data.
pub struct AqcBidiChannel {
    pub(crate) inner: aqc::AqcBidiChannel,
}

impl Typed for AqcBidiChannel {
    const TYPE_ID: TypeId = TypeId::new(0x7B446A10);
}

impl AqcBidiChannel {
    pub fn new(channel: aqc::AqcBidiChannel) -> Self {
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
    pub(crate) inner: aqc::AqcReceiveChannel,
}

impl Typed for AqcReceiverChannel {
    const TYPE_ID: TypeId = TypeId::new(0x62A97986);
}

impl AqcReceiverChannel {
    pub fn new(channel: aqc::AqcReceiveChannel) -> Self {
        Self { inner: channel }
    }
}

/// Container for an AQC Channel variant.
///
/// This needs to be destructured before it can be used, since C doesn't have
/// dataful enums.
pub struct AqcPeerChannel {
    pub(crate) inner: aqc::AqcPeerChannel,
}

impl Typed for AqcPeerChannel {
    const TYPE_ID: TypeId = TypeId::new(0x7A1D7BE9);
}

impl AqcPeerChannel {
    pub fn new(channel: aqc::AqcPeerChannel) -> Self {
        Self { inner: channel }
    }
}

/// An AQC stream that can both send and receive data.
pub struct AqcBidiStream {
    pub(crate) inner: aqc::AqcBidiStream,
    pub(crate) data: Option<bytes::Bytes>,
}

impl Typed for AqcBidiStream {
    const TYPE_ID: TypeId = TypeId::new(0xE084F73B);
}

impl AqcBidiStream {
    pub fn new(stream: aqc::AqcBidiStream) -> Self {
        Self {
            inner: stream,
            data: None,
        }
    }
}

/// An AQC stream that can only send data.
pub struct AqcSendStream {
    pub(crate) inner: aqc::AqcSendStream,
}

impl Typed for AqcSendStream {
    const TYPE_ID: TypeId = TypeId::new(0x8C03E403);
}

impl AqcSendStream {
    pub fn new(stream: aqc::AqcSendStream) -> Self {
        Self { inner: stream }
    }
}

/// An AQC stream that can only receive data.
pub struct AqcReceiveStream {
    pub(crate) inner: aqc::AqcReceiveStream,
    pub(crate) data: Option<bytes::Bytes>,
}

impl Typed for AqcReceiveStream {
    const TYPE_ID: TypeId = TypeId::new(0xB4D31DA6);
}

impl AqcReceiveStream {
    pub fn new(stream: aqc::AqcReceiveStream) -> Self {
        Self {
            inner: stream,
            data: None,
        }
    }
}
