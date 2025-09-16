//! AFC support.
use std::{fmt::Debug, sync::Arc};

use anyhow::Context;
use aranya_daemon_api::{
    AfcChannelId, AfcShmInfo, ChanOp, DaemonApiClient, DeviceId, LabelId, TeamId, CS,
};
use aranya_fast_channels::{
    shm::{Flag, Mode, ReadState},
    Client as AfcClient, Seq,
};
use serde::{Deserialize, Serialize};
use tarpc::context;
use tokio::sync::Mutex;
use tracing::debug;

use crate::error::{aranya_error, IpcError};

/// AFC sequence number identifying the position of a ciphertext in a channel.
#[derive(Debug)]
pub struct AfcSeq {
    seq: Seq,
}

impl AfcSeq {
    /// Convert AFC sequence object to `u64`.
    pub fn to_u64(&self) -> u64 {
        self.seq.to_u64()
    }
}

/// Possible errors that could happen when using Aranya Fast Channels.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AfcError {
    /// Unable to seal datagram.
    #[error("unable to seal datagram")]
    Seal(aranya_fast_channels::Error),

    /// Unable to open datagram.
    #[error("unable to open datagram")]
    Open(aranya_fast_channels::Error),

    /// Unable to parse shared-memory path.
    #[error("unable initialize shm")]
    Shm(anyhow::Error),

    /// No channel info found.
    #[error("no channel info found")]
    NoChannelInfoFound,

    /// Error parsing control message.
    #[error("failed to parse control message")]
    InvalidCtrlMessage(postcard::Error),

    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),
}

/// AFC control message sent to a peer when creating a channel.
#[derive(Debug, Serialize, Deserialize)]
pub struct AfcCtrl {
    data: Box<[u8]>,
}

impl AfcCtrl {
    /// Convert AFC control message to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Aranya Fast Channels handler for managing channels which allow encrypting/decrypting application data buffers.
pub struct AfcChannels {
    daemon: DaemonApiClient,
    // TODO: don't use mutex for shm reader aranya-core#399
    shm: Arc<Mutex<AfcShm>>,
}

// TODO: derive Debug on [`shm`] when [`AfcClient`] implements it.
impl Debug for AfcChannels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfcChannels")
            .field("daemon", &self.daemon)
            .finish_non_exhaustive()
    }
}

impl AfcChannels {
    /// The number of additional octets required to encrypt
    /// plaintext data.
    pub const OVERHEAD: usize = AfcClient::<ReadState<CS>>::OVERHEAD;

    pub(crate) fn new(daemon: DaemonApiClient, shm: Arc<Mutex<AfcShm>>) -> Self {
        Self { daemon, shm }
    }

    /// Create a bidirectional AFC channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub async fn create_bidi_channel(
        &self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> crate::Result<(AfcBidiChannel, AfcCtrl)> {
        let (ctrl, channel_id) = self
            .daemon
            .create_afc_bidi_channel(context::current(), team_id, peer_id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok((
            AfcBidiChannel {
                daemon: self.daemon.clone(),
                shm: self.shm.clone(),
                channel_id,
                label_id,
            },
            AfcCtrl { data: ctrl },
        ))
    }

    /// Create a unidirectional AFC send-only channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub async fn create_uni_send_channel(
        &self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> crate::Result<(AfcSendChannel, AfcCtrl)> {
        let (ctrl, channel_id) = self
            .daemon
            .create_afc_uni_send_channel(context::current(), team_id, peer_id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok((
            AfcSendChannel {
                daemon: self.daemon.clone(),
                shm: self.shm.clone(),
                channel_id,
                label_id,
            },
            AfcCtrl { data: ctrl },
        ))
    }

    /// Create a unidirectional AFC receive-only channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub async fn create_uni_recv_channel(
        &self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> crate::Result<(AfcReceiveChannel, AfcCtrl)> {
        let (ctrl, channel_id) = self
            .daemon
            .create_afc_uni_recv_channel(context::current(), team_id, peer_id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok((
            AfcReceiveChannel {
                daemon: self.daemon.clone(),
                shm: self.shm.clone(),
                channel_id,
                label_id,
            },
            AfcCtrl { data: ctrl },
        ))
    }

    /// Receive a `ctrl` message from a peer to create an AFC channel.
    pub async fn recv_ctrl(&self, team_id: TeamId, ctrl: AfcCtrl) -> crate::Result<AfcChannel> {
        let (label_id, channel_id, op) = self
            .daemon
            .receive_afc_ctrl(context::current(), team_id, ctrl.data)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        match op {
            ChanOp::RecvOnly => Ok(AfcChannel::Uni(AfcUniChannel::Receive(AfcReceiveChannel {
                daemon: self.daemon.clone(),
                shm: self.shm.clone(),
                channel_id,
                label_id,
            }))),
            ChanOp::SendOnly => Ok(AfcChannel::Uni(AfcUniChannel::Send(AfcSendChannel {
                daemon: self.daemon.clone(),
                shm: self.shm.clone(),
                channel_id,
                label_id,
            }))),
            ChanOp::SendRecv => Ok(AfcChannel::Bidi(AfcBidiChannel {
                daemon: self.daemon.clone(),
                shm: self.shm.clone(),
                channel_id,
                label_id,
            })),
        }
    }

    /// Create an AFC channel by removing channel key entry from shared memory.
    pub async fn delete_channel(&self, channel_id: AfcChannelId) -> crate::Result<()> {
        self.daemon
            .delete_afc_channel(context::current(), channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// An AFC channel.
#[derive(Debug)]
pub enum AfcChannel {
    /// A bidirectional channel.
    Bidi(AfcBidiChannel),
    /// A unidirectional channel.
    Uni(AfcUniChannel),
}

/// An unidirectional AFC channel.
#[derive(Debug)]
pub enum AfcUniChannel {
    /// A send channel.
    Send(AfcSendChannel),
    /// A receive channel.
    Receive(AfcReceiveChannel),
}

/// A bidirectional AFC channel.
#[derive(Debug)]
pub struct AfcBidiChannel {
    daemon: DaemonApiClient,
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl AfcBidiChannel {
    /// The AFC channel ID.
    pub fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    /// The AFC channel's label ID.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Encrypts and authenticates `plaintext` for a channel.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len() + AfcChannels::OVERHEAD` bytes
    /// long.
    pub async fn seal(&self, dst: &mut [u8], plaintext: &[u8]) -> Result<(), AfcError> {
        debug!(?self.channel_id, ?self.label_id, "seal");
        self.shm
            .lock()
            .await
            .0
            .seal(self.channel_id, dst, plaintext)
            .map_err(AfcError::Seal)?;
        Ok(())
    }

    /// Decrypts and authenticates `ciphertext` received from
    /// from `peer`.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// be at least `ciphertext.len() - AfcChannels::OVERHEAD` bytes
    /// long.
    ///
    /// It returns the cryptographically verified label and
    /// sequence number associated with the ciphertext.
    pub async fn open(&self, dst: &mut [u8], ciphertext: &[u8]) -> Result<AfcSeq, AfcError> {
        debug!(?self.channel_id, ?self.label_id, "open");
        let (_, seq) = self
            .shm
            .lock()
            .await
            .0
            .open(self.channel_id, dst, ciphertext)
            .map_err(AfcError::Open)?;
        Ok(AfcSeq { seq })
    }

    /// Delete the AFC channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.daemon
            .delete_afc_channel(context::current(), self.channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// A unidirectional AFC channel that can only send.
#[derive(Debug)]
pub struct AfcSendChannel {
    daemon: DaemonApiClient,
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl AfcSendChannel {
    /// The AFC channel ID.
    pub fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    /// The AFC channel's label ID.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Encrypts and authenticates `plaintext` for a channel.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len() + AfcChannels::OVERHEAD` bytes
    /// long.
    pub async fn seal(&self, dst: &mut [u8], plaintext: &[u8]) -> Result<(), AfcError> {
        debug!(?self.channel_id, ?self.label_id, "seal");
        self.shm
            .lock()
            .await
            .0
            .seal(self.channel_id, dst, plaintext)
            .map_err(AfcError::Seal)?;
        Ok(())
    }

    /// Delete the AFC channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.daemon
            .delete_afc_channel(context::current(), self.channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// A unidirectional AFC channel that can only receive.
#[derive(Debug)]
pub struct AfcReceiveChannel {
    daemon: DaemonApiClient,
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl AfcReceiveChannel {
    /// The AFC channel ID.
    pub fn channel_id(&self) -> AfcChannelId {
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
    /// be at least `ciphertext.len() - AfcChannels::OVERHEAD` bytes
    /// long.
    ///
    /// It returns the cryptographically verified label and
    /// sequence number associated with the ciphertext.
    pub async fn open(&self, dst: &mut [u8], ciphertext: &[u8]) -> Result<AfcSeq, AfcError> {
        debug!(?self.channel_id, ?self.label_id, "open");
        let (_, seq) = self
            .shm
            .lock()
            .await
            .0
            .open(self.channel_id, dst, ciphertext)
            .map_err(AfcError::Open)?;
        Ok(AfcSeq { seq })
    }

    /// Delete the AFC channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.daemon
            .delete_afc_channel(context::current(), self.channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// AFC shared memory.
pub(crate) struct AfcShm(AfcClient<ReadState<CS>>);

impl AfcShm {
    /// Open shared-memory to daemon's channel key list.
    pub fn new(afc_shm_info: &AfcShmInfo) -> Result<Self, AfcError> {
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
            .map_err(AfcError::Shm)?
        };

        Ok(Self(AfcClient::new(read)))
    }
}

impl Debug for AfcShm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfcShm").finish_non_exhaustive()
    }
}
