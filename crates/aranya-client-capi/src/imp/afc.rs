use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::afc;

#[derive(Debug)]
pub(crate) enum ChannelType {
    Bidi(afc::BidiChannel),
    Send(afc::SendChannel),
    Receive(afc::ReceiveChannel),
}

/// An AFC channel.
#[derive(Debug)]
pub struct AfcChannel {
    pub(crate) inner: ChannelType,
}

impl Typed for AfcChannel {
    const TYPE_ID: TypeId = TypeId::new(0xDC3130B2);
}

impl AfcChannel {
    pub fn new(channel: afc::Channel) -> Self {
        Self {
            inner: match channel {
                afc::Channel::Bidi(c) => ChannelType::Bidi(c),
                afc::Channel::Uni(c) => match c {
                    afc::UniChannel::Send(c) => ChannelType::Send(c),
                    afc::UniChannel::Receive(c) => ChannelType::Receive(c),
                },
            },
        }
    }

    pub fn new_bidi(bidi: afc::BidiChannel) -> Self {
        Self {
            inner: ChannelType::Bidi(bidi),
        }
    }

    pub fn new_send(send: afc::SendChannel) -> Self {
        Self {
            inner: ChannelType::Send(send),
        }
    }

    pub fn new_recv(recv: afc::ReceiveChannel) -> Self {
        Self {
            inner: ChannelType::Receive(recv),
        }
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
