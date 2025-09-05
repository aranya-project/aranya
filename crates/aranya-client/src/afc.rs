//! AFC support.
use std::{fmt::Debug, str::FromStr};

use anyhow::Context;
use aranya_crypto::{default::DefaultCipherSuite, CipherSuite};
use aranya_daemon_api::{AfcChannelId, ChanOp, LabelId, NetIdentifier, TeamId, CS};
use aranya_fast_channels::shm::{Flag, Mode, ReadState};
use tarpc::context;
use tracing::debug;

use crate::{
    error::{aranya_error, AfcError, IpcError},
    Client,
};

/// AFC control message sent to a peer when creating a channel.
pub type Ctrl = Vec<Box<[u8]>>;

/// Aranya Fast Channels handler for managing channels which allow encrypting/decrypting application data buffers.
#[derive(Debug)]
pub struct AfcChannels<'a> {
    client: &'a mut Client,
}

impl<'a> AfcChannels<'a> {
    pub(crate) fn new(client: &'a mut Client) -> Self {
        Self { client }
    }

    /// Create a bidirectional AFC channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub async fn create_bidi_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> crate::Result<(AfcBidiChannel<'_>, Ctrl)> {
        let (ctrl, channel_id) = self
            .client
            .daemon
            .create_afc_bidi_channel(context::current(), team_id, peer, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok((
            AfcBidiChannel {
                client: self.client,
                channel_id,
                label_id,
            },
            ctrl,
        ))
    }

    /// Create a unidirectional AFC channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub async fn create_uni_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> crate::Result<(AfcSendChannel<'_>, Ctrl)> {
        let (ctrl, channel_id) = self
            .client
            .daemon
            .create_afc_uni_channel(context::current(), team_id, peer, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok((
            AfcSendChannel {
                client: self.client,
                channel_id,
                label_id,
            },
            ctrl,
        ))
    }

    /// Receive a `ctrl` message from a peer to create an AFC channel.
    pub async fn receive_channel(
        &mut self,
        team_id: TeamId,
        ctrl: Ctrl,
    ) -> crate::Result<AfcChannel<'_>> {
        let (label_id, channel_id, op) = self
            .client
            .daemon
            .receive_afc_ctrl(context::current(), team_id, ctrl)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        match op {
            ChanOp::RecvOnly => Ok(AfcChannel::Uni(AfcUniChannel::Receive(AfcReceiveChannel {
                client: self.client,
                channel_id,
                label_id,
            }))),
            ChanOp::SendOnly => Ok(AfcChannel::Uni(AfcUniChannel::Send(AfcSendChannel {
                client: self.client,
                channel_id,
                label_id,
            }))),
            ChanOp::SendRecv => Ok(AfcChannel::Bidi(AfcBidiChannel {
                client: self.client,
                channel_id,
                label_id,
            })),
        }
    }

    /// Create an AFC channel by removing channel key entry from shared memory.
    pub async fn delete_channel(&self, chan: AfcChannel<'_>) -> crate::Result<()> {
        let channel_id = match chan {
            AfcChannel::Bidi(chan) => chan.channel_id,
            AfcChannel::Uni(chan) => match chan {
                AfcUniChannel::Send(chan) => chan.channel_id,
                AfcUniChannel::Receive(chan) => chan.channel_id,
            },
        };
        self.client
            .daemon
            .delete_afc_channel(context::current(), channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// An AFC channel.
#[derive(Debug)]
pub enum AfcChannel<'a> {
    /// A bidirectional channel.
    Bidi(AfcBidiChannel<'a>),
    /// A unidirectional channel.
    Uni(AfcUniChannel<'a>),
}

/// An unidirectional AFC channel.
#[derive(Debug)]
pub enum AfcUniChannel<'a> {
    /// A send channel.
    Send(AfcSendChannel<'a>),
    /// A receive channel.
    Receive(AfcReceiveChannel<'a>),
}

/// A bidirectional AFC channel.
#[derive(Debug)]
pub struct AfcBidiChannel<'a> {
    client: &'a mut Client,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl Seal for AfcBidiChannel<'_> {
    fn seal(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError> {
        self.client
            .afc
            .seal(
                self.channel_id,
                self.label_id.into_id().into(),
                ciphertext,
                plaintext,
            )
            .map_err(AfcError::Seal)?;
        Ok(())
    }
}

impl Open for AfcBidiChannel<'_> {
    fn open(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), AfcError> {
        self.client
            .afc
            .open(
                self.channel_id,
                self.label_id.into_id().into(),
                plaintext,
                ciphertext,
            )
            .map_err(AfcError::Open)?;
        Ok(())
    }
}

/// A unidirectional AFC channel that can only send.
#[derive(Debug)]
pub struct AfcSendChannel<'a> {
    client: &'a mut Client,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl Seal for AfcSendChannel<'_> {
    fn seal(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError> {
        self.client
            .afc
            .seal(
                self.channel_id,
                self.label_id.into_id().into(),
                ciphertext,
                plaintext,
            )
            .map_err(AfcError::Seal)?;
        Ok(())
    }
}

/// A unidirectional AFC channel that can only receive.
#[derive(Debug)]
pub struct AfcReceiveChannel<'a> {
    client: &'a mut Client,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl Open for AfcReceiveChannel<'_> {
    fn open(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), AfcError> {
        self.client
            .afc
            .open(
                self.channel_id,
                self.label_id.into_id().into(),
                plaintext,
                ciphertext,
            )
            .map_err(AfcError::Open)?;
        Ok(())
    }
}

/// AFC channels that can seal datagrams should implement this trait.
pub trait Seal {
    /// Seal a plaintext datagram into ciphertext.
    fn seal(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError>;
}

/// AFC channels that can open datagrams should implement this trait.
pub trait Open {
    /// Open a ciphertext datagram and return the plaintext.
    fn open(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), AfcError>;
}

/// AFC shared memory.
pub struct AfcShm {
    /// Handle to shared-memory with RW permissions.
    pub read: ReadState<DefaultCipherSuite>,
}

impl AfcShm
where
    CS: CipherSuite,
{
    /// Open shared-memory to daemon's channel key list.
    pub fn new(shm_path: String, max_chans: usize) -> Result<Self, AfcError> {
        // TODO: issue stellar-tapestry#34
        // afc::shm{ReadState, WriteState} doesn't work on linux/arm64
        debug!(?shm_path, "setting up afc shm read side");
        let read = {
            let path = aranya_util::ShmPathBuf::from_str(&shm_path)
                .context("unable to parse AFC shared memory path")
                .map_err(AfcError::Shm)?;
            ReadState::open(&path, Flag::OpenOnly, Mode::ReadWrite, max_chans)
                .context(format!("unable to open `WriteState`: {:?}", shm_path))
                .map_err(AfcError::Shm)?
        };

        Ok(Self { read })
    }
}

impl Debug for AfcShm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfcShm").finish()
    }
}
