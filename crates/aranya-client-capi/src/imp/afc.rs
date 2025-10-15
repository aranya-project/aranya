//! AFC-specific utilities for the Aranya Client C API.
#![cfg(feature = "afc")]

use aranya_client::afc;

/// Send channel.
#[derive(Debug)]
pub struct AfcSendChannel(pub afc::SendChannel);

/// Receive channel.
#[derive(Debug)]
pub struct AfcReceiveChannel(pub afc::ReceiveChannel);

/// A control message, for creating the other end of a channel.
#[repr(transparent)]
#[derive(Debug)]
pub struct AfcCtrlMsg(pub(crate) afc::CtrlMsg);

impl From<afc::CtrlMsg> for AfcCtrlMsg {
    fn from(msg: afc::CtrlMsg) -> Self {
        Self(msg)
    }
}

/// A sequence number, for reordering messages.
#[repr(transparent)]
#[derive(Debug)]
pub struct AfcSeq(pub(crate) afc::Seq);

impl From<afc::Seq> for AfcSeq {
    fn from(seq: afc::Seq) -> Self {
        Self(seq)
    }
}
