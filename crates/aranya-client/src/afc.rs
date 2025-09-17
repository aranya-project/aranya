//! AFC support.
use std::{fmt::Debug, sync::Arc};

use anyhow::Context;
use aranya_daemon_api::{self as api, AfcShmInfo, ChanOp, DaemonApiClient, CS};
use aranya_fast_channels::{
    self as afc,
    shm::{Flag, Mode, ReadState},
    Client as AfcClient,
};
use serde::{Deserialize, Serialize};
use tarpc::context;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    error::{aranya_error, IpcError},
    DeviceId, LabelId, Result, TeamId,
};

/// Locally unique AFC channel ID.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct ChannelId(api::AfcChannelId);

/// AFC sequence number identifying the position of a ciphertext in a channel.
#[derive(Copy, Clone, Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Seq(afc::Seq);

impl Seq {
    /// Convert AFC sequence object to `u64`.
    pub fn to_u64(self) -> u64 {
        self.0.to_u64()
    }
}

/// AFC control message sent to a peer when creating a channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ctrl(Box<[u8]>);

impl Ctrl {
    /// Convert AFC control message to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Possible errors that could happen when using Aranya Fast Channels.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Unable to seal datagram.
    #[error("unable to seal datagram")]
    Seal(aranya_fast_channels::Error),

    /// Unable to open datagram.
    #[error("unable to open datagram")]
    Open(aranya_fast_channels::Error),

    /// Unable to connect to AFC channel keys IPC.
    #[error("unable to connect to AFC channel keys IPC")]
    AfcIpc(anyhow::Error),

    /// No channel info found.
    #[error("no channel info found")]
    NoChannelInfoFound,

    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),
}

/// Aranya Fast Channels handler for managing channels which allow encrypting/decrypting application data buffers.
pub struct Channels {
    daemon: DaemonApiClient,
    // TODO: don't use mutex for shm reader aranya-core#399
    keys: Arc<Mutex<ChannelKeys>>,
}

// TODO: derive Debug on [`keys`] when [`AfcClient`] implements it.
impl Debug for Channels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfcChannels")
            .field("daemon", &self.daemon)
            .finish_non_exhaustive()
    }
}

impl Channels {
    /// The number of additional octets required to encrypt
    /// plaintext data.
    pub const OVERHEAD: usize = AfcClient::<ReadState<CS>>::OVERHEAD;

    pub(crate) fn new(daemon: DaemonApiClient, keys: Arc<Mutex<ChannelKeys>>) -> Self {
        Self { daemon, keys }
    }

    /// Create a bidirectional AFC channel [`BidiChannel`] between two peers.
    ///
    /// The creator of the channel will have a bidirectional channel [`BidiChannel`] that can `open()` and `seal()` data.
    ///
    /// Once the peer processes the [`Ctrl`] message with `recv_ctrl()`,
    /// it will have a corresponding bidirectional channel [`BidiChannel`] object that can also `open()` and `seal()` data.
    ///
    /// To send data from one peer to the other:
    /// - Invoke `seal()` on the data to obtain a ciphertext buffer.
    /// - Send the ciphertext to the peer via any network transport.
    /// - On the peer, invoke `open()` on the ciphertext to obtain the plaintext.
    ///
    /// Returns:
    /// - A bidirectional channel object that can `open()` and `seal()` data.
    /// - A [`Ctrl`] message to send to the peer.
    pub async fn create_bidi_channel(
        &self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> Result<(BidiChannel, Ctrl)> {
        let (ctrl, channel_id) = self
            .daemon
            .create_afc_bidi_channel(
                context::current(),
                team_id.into_id().into(),
                peer_id.into_id().into(),
                label_id.into_id().into(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        let chan = BidiChannel {
            daemon: self.daemon.clone(),
            keys: self.keys.clone(),
            channel_id: ChannelId(channel_id),
            label_id: label_id.into_id().into(),
        };
        Ok((chan, Ctrl(ctrl)))
    }

    /// Create a unidirectional AFC send-only channel [`SendChannel`].
    ///
    /// The creator of the channel will have a unidirectional channel [`SendChannel`] that can only `seal()` data.
    ///
    /// Once the peer processes the [`Ctrl`] message with `recv_ctrl()`,
    /// it will have a corresponding unidirectional channel [`ReceiveChannel`] object that can only `open()` data.
    ///
    /// To send data from the creator of the channel to the peer:
    /// - Invoke `seal()` on the data to obtain a ciphertext buffer.
    /// - Send the ciphertext to the peer via any network transport.
    /// - On the peer, invoke `open()` on the ciphertext to obtain the plaintext.
    ///
    /// Returns:
    /// - A unidirectional channel [`SendChannel`] object that can only `seal()` data.
    /// - A [`Ctrl`] message to send to the peer.
    pub async fn create_uni_send_channel(
        &self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> Result<(SendChannel, Ctrl)> {
        let (ctrl, channel_id) = self
            .daemon
            .create_afc_uni_send_channel(
                context::current(),
                team_id.into_id().into(),
                peer_id.into_id().into(),
                label_id.into_id().into(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        let chan = SendChannel {
            daemon: self.daemon.clone(),
            keys: self.keys.clone(),
            channel_id: ChannelId(channel_id),
            label_id: label_id.into_id().into(),
        };
        Ok((chan, Ctrl(ctrl)))
    }

    /// Create a unidirectional AFC receive-only channel [`ReceiveChannel`].
    ///
    /// The creator of the channel will have a unidirectional channel [`ReceiveChannel`] that can only `open()` data.
    ///
    /// Once the peer processes the [`Ctrl`] message with `recv_ctrl()`,
    /// it will have a corresponding unidirectional channel [`SendChannel`] object that can only `seal()` data.
    ///
    /// To send data from the peer to the creator of the channel:
    /// - On the peer, invoke `seal()` on the data to obtain a ciphertext buffer.
    /// - Send the ciphertext to the creator of the channel via any network transport.
    /// - On the creator, invoke `open()` on the ciphertext to obtain the plaintext.
    ///
    /// Returns:
    /// - A unidirectional channel [`ReceiveChannel`] object that can only `open()` data.
    /// - A [`Ctrl`] message to send to the peer.
    pub async fn create_uni_recv_channel(
        &self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> Result<(ReceiveChannel, Ctrl)> {
        let (ctrl, channel_id) = self
            .daemon
            .create_afc_uni_recv_channel(
                context::current(),
                team_id.into_id().into(),
                peer_id.into_id().into(),
                label_id.into_id().into(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        let chan = ReceiveChannel {
            daemon: self.daemon.clone(),
            keys: self.keys.clone(),
            channel_id: ChannelId(channel_id),
            label_id: label_id.into_id().into(),
        };
        Ok((chan, Ctrl(ctrl)))
    }

    /// Receive a [`Ctrl`] message from a peer to create a corresponding AFC channel.
    ///
    /// The type of channel returned by this method depends on which type of channel the peer created:
    /// - If the peer created a [`BidiChannel`], this will return a [`BidiChannel`]
    /// - If the peer created a [`SendChannel`], this will return a [`ReceiveChannel`]
    /// - If the peer created a [`ReceiveChannel`], this will return a [`SendChannel`]
    ///
    /// Returns a [`Channel`] enum that can be matched into any of the following channel types:
    /// - [`BidiChannel`]
    /// - [`SendChannel`]
    /// - [`ReceiveChannel`]
    pub async fn recv_ctrl(&self, team_id: TeamId, ctrl: Ctrl) -> Result<Channel> {
        let (label_id, channel_id, op) = self
            .daemon
            .receive_afc_ctrl(context::current(), team_id.into_id().into(), ctrl.0)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        match op {
            ChanOp::RecvOnly => Ok(Channel::Uni(UniChannel::Receive(ReceiveChannel {
                daemon: self.daemon.clone(),
                keys: self.keys.clone(),
                channel_id: ChannelId(channel_id),
                label_id: label_id.into_id().into(),
            }))),
            ChanOp::SendOnly => Ok(Channel::Uni(UniChannel::Send(SendChannel {
                daemon: self.daemon.clone(),
                keys: self.keys.clone(),
                channel_id: ChannelId(channel_id),
                label_id: label_id.into_id().into(),
            }))),
            ChanOp::SendRecv => Ok(Channel::Bidi(BidiChannel {
                daemon: self.daemon.clone(),
                keys: self.keys.clone(),
                channel_id: ChannelId(channel_id),
                label_id: label_id.into_id().into(),
            })),
        }
    }

    /// Delete an AFC channel by removing channel key entry from the AFC IPC.
    pub async fn delete_channel(&self, channel_id: ChannelId) -> Result<()> {
        self.daemon
            .delete_afc_channel(context::current(), channel_id.0)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// An AFC channel.
#[derive(Clone, Debug)]
pub enum Channel {
    /// A bidirectional channel.
    Bidi(BidiChannel),
    /// A unidirectional channel.
    Uni(UniChannel),
}

/// An unidirectional AFC channel.
#[derive(Clone, Debug)]
pub enum UniChannel {
    /// A send channel.
    Send(SendChannel),
    /// A receive channel.
    Receive(ReceiveChannel),
}

/// A bidirectional AFC channel.
#[derive(Clone, Debug)]
pub struct BidiChannel {
    daemon: DaemonApiClient,
    keys: Arc<Mutex<ChannelKeys>>,
    channel_id: ChannelId,
    label_id: LabelId,
}

impl BidiChannel {
    /// The AFC channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    /// The AFC channel's label ID.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Encrypts and authenticates `plaintext` for a channel.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len() + Channels::OVERHEAD` bytes
    /// long.
    pub async fn seal(&self, dst: &mut [u8], plaintext: &[u8]) -> Result<(), Error> {
        debug!(?self.channel_id, ?self.label_id, "seal");
        self.keys
            .lock()
            .await
            .0
            .seal(self.channel_id.0, dst, plaintext)
            .map_err(Error::Seal)?;
        Ok(())
    }

    /// Decrypts and authenticates `ciphertext` received from
    /// from `peer`.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// be at least `ciphertext.len() - Channels::OVERHEAD` bytes
    /// long.
    ///
    /// It returns the cryptographically verified label and
    /// sequence number associated with the ciphertext.
    pub async fn open(&self, dst: &mut [u8], ciphertext: &[u8]) -> Result<Seq, Error> {
        debug!(?self.channel_id, ?self.label_id, "open");
        let (label_id, seq) = self
            .keys
            .lock()
            .await
            .0
            .open(self.channel_id.0, dst, ciphertext)
            .map_err(Error::Open)?;
        debug_assert_eq!(label_id.into_id(), self.label_id.into_id());
        Ok(Seq(seq))
    }

    /// Delete the AFC channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.daemon
            .delete_afc_channel(context::current(), self.channel_id.0)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// A unidirectional AFC channel that can only send.
#[derive(Clone, Debug)]
pub struct SendChannel {
    daemon: DaemonApiClient,
    keys: Arc<Mutex<ChannelKeys>>,
    channel_id: ChannelId,
    label_id: LabelId,
}

impl SendChannel {
    /// The AFC channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    /// The AFC channel's label ID.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Encrypts and authenticates `plaintext` for a channel.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len() + Channels::OVERHEAD` bytes
    /// long.
    pub async fn seal(&self, dst: &mut [u8], plaintext: &[u8]) -> Result<(), Error> {
        debug!(?self.channel_id, ?self.label_id, "seal");
        self.keys
            .lock()
            .await
            .0
            .seal(self.channel_id.0, dst, plaintext)
            .map_err(Error::Seal)?;
        Ok(())
    }

    /// Delete the AFC channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.daemon
            .delete_afc_channel(context::current(), self.channel_id.0)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// A unidirectional AFC channel that can only receive.
#[derive(Clone, Debug)]
pub struct ReceiveChannel {
    daemon: DaemonApiClient,
    keys: Arc<Mutex<ChannelKeys>>,
    channel_id: ChannelId,
    label_id: LabelId,
}

impl ReceiveChannel {
    /// The AFC channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    /// The AFC channel's label ID.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Decrypts and authenticates `ciphertext` received from
    /// from `peer`.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// be at least `ciphertext.len() - Channels::OVERHEAD` bytes
    /// long.
    ///
    /// It returns the cryptographically verified label and
    /// sequence number associated with the ciphertext.
    pub async fn open(&self, dst: &mut [u8], ciphertext: &[u8]) -> Result<Seq, Error> {
        debug!(?self.channel_id, ?self.label_id, "open");
        let (label_id, seq) = self
            .keys
            .lock()
            .await
            .0
            .open(self.channel_id.0, dst, ciphertext)
            .map_err(Error::Open)?;
        debug_assert_eq!(label_id.into_id(), self.label_id.into_id());
        Ok(Seq(seq))
    }

    /// Delete the AFC channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.daemon
            .delete_afc_channel(context::current(), self.channel_id.0)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// AFC Channel Keys.
pub(crate) struct ChannelKeys(AfcClient<ReadState<CS>>);

impl ChannelKeys {
    /// Open shared-memory client to daemon's channel key list.
    pub fn new(afc_shm_info: &AfcShmInfo) -> Result<Self, Error> {
        // TODO: issue stellar-tapestry#34
        // afc::shm{ReadState, WriteState} doesn't work on linux/arm64
        debug!(
            "setting up afc shm read side: {:?}",
            afc_shm_info.path.clone()
        );
        let read = {
            ReadState::open(
                afc_shm_info.path.clone(),
                Flag::OpenOnly,
                Mode::ReadWrite,
                afc_shm_info.max_chans,
            )
            .context(format!(
                "unable to open `WriteState`: {:?}",
                afc_shm_info.path
            ))
            .map_err(Error::AfcIpc)?
        };

        Ok(Self(AfcClient::new(read)))
    }
}

impl Debug for ChannelKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfcChannelKeys").finish_non_exhaustive()
    }
}
