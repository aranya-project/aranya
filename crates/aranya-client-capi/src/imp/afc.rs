//! AFC-specific utilities for the Aranya Client C API.
#![cfg(feature = "afc")]

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::afc;

/// All channel variants.
#[derive(Debug)]
pub enum AfcChannel {
    Bidi(afc::BidiChannel),
    Send(afc::SendChannel),
    Receive(afc::ReceiveChannel),
}

impl Typed for AfcChannel {
    const TYPE_ID: TypeId = TypeId::new(0xDC3130B2);
}

impl From<afc::Channel> for AfcChannel {
    fn from(channel: afc::Channel) -> Self {
        match channel {
            afc::Channel::Bidi(c) => Self::Bidi(c),
            afc::Channel::Send(c) => Self::Send(c),
            afc::Channel::Recv(c) => Self::Receive(c),
        }
    }
}

impl From<afc::BidiChannel> for AfcChannel {
    fn from(channel: afc::BidiChannel) -> Self {
        Self::Bidi(channel)
    }
}

impl From<afc::SendChannel> for AfcChannel {
    fn from(channel: afc::SendChannel) -> Self {
        Self::Send(channel)
    }
}

impl From<afc::ReceiveChannel> for AfcChannel {
    fn from(channel: afc::ReceiveChannel) -> Self {
        Self::Receive(channel)
    }
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
pub struct AfcSeq(afc::Seq);

impl Typed for AfcSeq {
    const TYPE_ID: TypeId = TypeId::new(0xC4DCE0C0);
}

impl From<afc::Seq> for AfcSeq {
    fn from(seq: afc::Seq) -> Self {
        Self(seq)
    }
}
