#![cfg(feature = "aqc")]

use core::{
    mem::{self, MaybeUninit},
    ptr,
};

use aranya_client::aqc;
use bytes::{Buf as _, Bytes};

/// An AQC channel that can both send and receive data.
#[derive(Debug)]
pub struct AqcBidiChannel {
    pub(crate) inner: aqc::AqcBidiChannel,
}

impl AqcBidiChannel {
    pub fn new(channel: aqc::AqcBidiChannel) -> Self {
        Self { inner: channel }
    }
}

/// An AQC channel that can only send data.
#[derive(Debug)]
pub struct AqcSendChannel {
    pub(crate) inner: aqc::AqcSendChannel,
}

impl AqcSendChannel {
    pub fn new(channel: aqc::AqcSendChannel) -> Self {
        Self { inner: channel }
    }
}

/// An AQC channel that can only receive data.
#[derive(Debug)]
pub struct AqcReceiveChannel {
    pub(crate) inner: aqc::AqcReceiveChannel,
}

impl AqcReceiveChannel {
    pub fn new(channel: aqc::AqcReceiveChannel) -> Self {
        Self { inner: channel }
    }
}

/// Container for an AQC Channel variant.
///
/// This needs to be destructured before it can be used, since C doesn't have
/// dataful enums.
#[derive(Debug)]
pub struct AqcPeerChannel {
    pub(crate) inner: aqc::AqcPeerChannel,
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
