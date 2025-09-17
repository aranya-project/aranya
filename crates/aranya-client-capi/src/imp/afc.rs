/*
use core::{
    mem::{self, MaybeUninit},
    ptr,
};

use bytes::{Buf as _, Bytes};
*/

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::afc;

/// An AFC channel that can both send and receive data.
#[derive(Debug)]
pub struct AfcBidiChannel {
    pub(crate) inner: afc::BidiChannel,
}

impl Typed for AfcBidiChannel {
    const TYPE_ID: TypeId = TypeId::new(0x7A59A0AF);
}

impl AfcBidiChannel {
    pub fn new(channel: afc::BidiChannel) -> AfcBidiChannel {
        Self { inner: channel }
    }
}

/// An AFC control message, for ephemeral channels.
#[derive(Debug)]
pub struct AfcCtrl {
    pub(crate) inner: afc::Ctrl,
}

impl Typed for AfcCtrl {
    const TYPE_ID: TypeId = TypeId::new(0xB421D1CE);
}

impl AfcCtrl {
    pub fn new(ctrl: afc::Ctrl) -> AfcCtrl {
        Self { inner: ctrl }
    }
}

/// An AFC channel that can only send data.
#[derive(Debug)]
pub struct AfcSendChannel {
    pub(crate) inner: afc::SendChannel,
}

impl Typed for AfcSendChannel {
    const TYPE_ID: TypeId = TypeId::new(0xFF884EE4);
}

impl AfcSendChannel {
    pub fn new(channel: afc::SendChannel) -> Self {
        Self { inner: channel }
    }
}

/// An AFC channel that can only receive data.
#[derive(Debug)]
pub struct AfcReceiveChannel {
    pub(crate) inner: afc::ReceiveChannel,
}

impl Typed for AfcReceiveChannel {
    const TYPE_ID: TypeId = TypeId::new(0xEF92C638);
}

impl AfcReceiveChannel {
    pub fn new(channel: afc::ReceiveChannel) -> Self {
        Self { inner: channel }
    }
}

/// An AFC channel.
#[derive(Debug)]
pub struct AfcChannel {
    pub(crate) inner: afc::Channel,
}

impl Typed for AfcChannel {
    const TYPE_ID: TypeId = TypeId::new(0xDC3130B2);
}

impl AfcChannel {
    pub fn new(channel: afc::Channel) -> Self {
        Self { inner: channel }
    }
}
/*
/// Container for an AQC Channel variant.
///
/// This needs to be destructured before it can be used, since C doesn't have
/// dataful enums.
#[derive(Debug)]
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
#[derive(Debug)]
pub struct AqcBidiStream {
    pub(crate) inner: aqc::AqcBidiStream,
    pub(crate) data: Bytes,
}

impl Typed for AqcBidiStream {
    const TYPE_ID: TypeId = TypeId::new(0xE084F73B);
}

impl AqcBidiStream {
    pub fn new(stream: aqc::AqcBidiStream) -> Self {
        Self {
            inner: stream,
            data: Bytes::new(),
        }
    }
}

/// An AQC stream that can only send data.
#[derive(Debug)]
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
#[derive(Debug)]
pub struct AqcReceiveStream {
    pub(crate) inner: aqc::AqcReceiveStream,
    pub(crate) data: Bytes,
}

impl Typed for AqcReceiveStream {
    const TYPE_ID: TypeId = TypeId::new(0xB4D31DA6);
}

impl AqcReceiveStream {
    pub fn new(stream: aqc::AqcReceiveStream) -> Self {
        Self {
            inner: stream,
            data: Bytes::new(),
        }
    }
}

/// Writes bytes into `buffer` from `bytes`, advancing them both.
///
/// Returns the number of bytes written.
pub(crate) fn consume_bytes(buffer: &mut &mut [MaybeUninit<u8>], bytes: &mut Bytes) -> usize {
    let len = core::cmp::min(bytes.len(), buffer.len());

    // SAFETY: &[T] and &[MaybeUninit<T>] have the same layout.
    let src =
        unsafe { &*(ptr::from_ref::<[u8]>(&bytes.as_ref()[..len]) as *const [MaybeUninit<u8>]) };
    let dst = &mut (*buffer)[..len];
    dst.copy_from_slice(src);

    *buffer = &mut mem::take(buffer)[len..];
    bytes.advance(len);

    len
}
*/
