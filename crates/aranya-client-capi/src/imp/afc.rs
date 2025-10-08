//! AFC-specific utilities for the Aranya Client C API.
#![cfg(feature = "afc")]

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::afc;

/// Send channel.
#[derive(Debug)]
pub struct AfcSendChannel(pub afc::SendChannel);

impl Typed for AfcSendChannel {
    const TYPE_ID: TypeId = TypeId::new(0xDC3130B2);
}

/// Receive channel.
#[derive(Debug)]
pub struct AfcReceiveChannel(pub afc::ReceiveChannel);

impl Typed for AfcReceiveChannel {
    const TYPE_ID: TypeId = TypeId::new(0xDC3130B2);
}

/// A control message, for creating the other end of a channel.
#[repr(transparent)]
#[derive(Debug)]
pub struct AfcCtrlMsg(pub(crate) afc::CtrlMsg);

impl Typed for AfcCtrlMsg {
    const TYPE_ID: TypeId = TypeId::new(0xB421D1CE);
}

impl From<afc::CtrlMsg> for AfcCtrlMsg {
    fn from(msg: afc::CtrlMsg) -> Self {
        Self(msg)
    }
}

/// A sequence number, for reordering messages.
#[repr(transparent)]
#[derive(Debug)]
pub struct AfcSeq(pub(crate) afc::Seq);

impl Typed for AfcSeq {
    const TYPE_ID: TypeId = TypeId::new(0xC4DCE0C0);
}

impl From<afc::Seq> for AfcSeq {
    fn from(seq: afc::Seq) -> Self {
        Self(seq)
    }
}
