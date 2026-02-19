//! AFC support.

#![cfg(feature = "afc")]
#![cfg_attr(docsrs, doc(cfg(feature = "afc")))]

use core::fmt;
use std::{
    fmt::{Debug, Display},
    sync::{Arc, Mutex},
};

use anyhow::Context;
use aranya_daemon_api::{AfcChannelId, AfcLocalChannelId, AfcShmInfo, DaemonApiClient, CS};
use aranya_fast_channels::{
    self as afc,
    shm::{Flag, Mode, ReadState},
    AfcState, Client as AfcClient,
};
use derive_where::derive_where;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{

    error::{aranya_error, IpcError},
    util::{rpc_context, ApiConv as _},
    DeviceId, LabelId, Result, TeamId,
};

/// The sequence number (position) of a message sent in a channel.
///
/// Sequence numbers are monotonically increasing; each call to `seal`
/// produces a ciphertext whose sequence number is greater than the
/// sequence number for the ciphertext produced by the previous call to
/// `seal`.
///
/// Each call to `open` cryptographically verifies that the ciphertext's sequence
/// number has not been tampered with. It does not verify anything else about
/// the sequence number.
///
/// Sequence numbers are [comparable][Ord] and can be used to implement
/// message reordering or replay protection (by rejecting duplicate sequence numbers).
#[derive(Copy, Clone, Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Seq(afc::Seq);

/// Control message sent to a peer when creating a channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CtrlMsg(Box<[u8]>);

impl CtrlMsg {
    /// Convert control message to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Box<[u8]>> for CtrlMsg {
    fn from(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

/// A globally unique channel ID.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChannelId {
    #[doc(hidden)]
    pub __id: AfcChannelId,
}

impl Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.__id, f)
    }
}

/// AFC seal error.
#[derive(Debug, thiserror::Error)]
pub struct AfcSealError(
    #[allow(dead_code, reason = "Don't expose internal error type in public API")]
    aranya_fast_channels::Error,
);

impl Display for AfcSealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// AFC open error.
#[derive(Debug, thiserror::Error)]
pub struct AfcOpenError(
    #[allow(dead_code, reason = "Don't expose internal error type in public API")]
    aranya_fast_channels::Error,
);

impl Display for AfcOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// Possible errors that could happen when using Aranya Fast Channels.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Unable to seal datagram.
    #[error("unable to seal datagram")]
    Seal(#[from] AfcSealError),

    /// Unable to open datagram.
    #[error("unable to open datagram")]
    Open(#[from] AfcOpenError),

    /// Unable to connect to channel keys IPC.
    #[error("unable to connect to channel keys IPC")]
    AfcIpc(#[from] anyhow::Error),

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
    keys: Arc<ChannelKeys>,
}

// TODO: derive Debug on [`keys`] when [`AfcClient`] implements it.
impl Debug for Channels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channels")
            .field("daemon", &self.daemon)
            .finish_non_exhaustive()
    }
}

impl Channels {
    /// The number of additional octets required to encrypt
    /// plaintext data.
    pub const OVERHEAD: usize = AfcClient::<ReadState<CS>>::OVERHEAD;

    pub(crate) fn new(daemon: DaemonApiClient, keys: Arc<ChannelKeys>) -> Self {
        Self { daemon, keys }
    }

    /// Create a unidirectional send-only channel [`SendChannel`].
    ///
    /// The creator of the channel will have a unidirectional channel [`SendChannel`] that can only `seal()` data.
    ///
    /// Once the peer processes the [`CtrlMsg`] message with `accept_channel()`,
    /// it will have a corresponding unidirectional channel [`ReceiveChannel`] object that can only `open()` data.
    ///
    /// To send data from the creator of the channel to the peer:
    /// - Invoke `seal()` on the data to obtain a ciphertext buffer.
    /// - Send the ciphertext to the peer via any network transport.
    /// - On the peer, invoke `open()` on the ciphertext to obtain the plaintext.
    ///
    /// Returns:
    /// - A unidirectional channel [`SendChannel`] object that can only `seal()` data.
    /// - A [`CtrlMsg`] message to send to the peer.
    pub async fn create_channel(
        &self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> Result<(SendChannel, CtrlMsg)> {
        let info = self
            .daemon
            .create_afc_channel(
                rpc_context(),
                team_id.into_api(),
                peer_id.into_api(),
                label_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        let seal_ctx = self
            .keys
            .0
            .setup_seal_ctx(info.local_channel_id)
            .map_err(AfcSealError)
            .map_err(Error::Seal)?;
        let chan = SendChannel {
            daemon: self.daemon.clone(),
            keys: self.keys.clone(),
            channel_id: ChannelId {
                __id: info.channel_id,
            },
            local_channel_id: info.local_channel_id,
            label_id,
            peer_id,
            seal_ctx: Box::new(seal_ctx),
        };
        Ok((chan, CtrlMsg(info.ctrl)))
    }

    /// Receive a [`CtrlMsg`] message from a peer to create a corresponding receive channel.
    pub async fn accept_channel(&self, team_id: TeamId, ctrl: CtrlMsg) -> Result<ReceiveChannel> {
        let info = self
            .daemon
            .accept_afc_channel(rpc_context(), team_id.into_api(), ctrl.0)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        let open_ctx = self
            .keys
            .0
            .setup_open_ctx(info.local_channel_id)
            .map_err(AfcSealError)
            .map_err(Error::Seal)?;
        Ok(ReceiveChannel {
            daemon: self.daemon.clone(),
            keys: self.keys.clone(),
            channel_id: ChannelId {
                __id: info.channel_id,
            },
            local_channel_id: info.local_channel_id,
            label_id: LabelId::from_api(info.label_id),
            peer_id: DeviceId::from_api(info.peer_id),
            open_ctx: Arc::new(Mutex::new(open_ctx)),
        })
    }
}

/// A unidirectional channel that can only send.
#[derive_where(Debug)]
pub struct SendChannel {
    daemon: DaemonApiClient,
    keys: Arc<ChannelKeys>,
    channel_id: ChannelId,
    local_channel_id: AfcLocalChannelId,
    label_id: LabelId,
    peer_id: DeviceId,
    #[derive_where(skip(Debug))]
    seal_ctx: Box<<ReadState<CS> as AfcState>::SealCtx>,
}

impl SendChannel {
    /// The channel's unique ID.
    pub fn id(&self) -> ChannelId {
        self.channel_id
    }

    /// The channel's label ID.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// The device ID of the peer on the other side of the channel.
    pub fn peer_id(&self) -> DeviceId {
        self.peer_id
    }

    /// Encrypts and authenticates `plaintext` for a channel.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len() + Channels::OVERHEAD` bytes
    /// long.
    ///
    /// Note: it is an error to invoke this method after the channel has been deleted.
    ///
    /// # Panics
    ///
    /// Will panic on poisoned internal mutexes.
    pub fn seal(&mut self, dst: &mut [u8], plaintext: &[u8]) -> Result<(), Error> {
        debug!(?self.local_channel_id, ?self.label_id, "seal");
        self.keys
            .0
            .seal(&mut self.seal_ctx, dst, plaintext)
            .map_err(AfcSealError)
            .map_err(Error::Seal)?;
        Ok(())
    }

    /// Delete the channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.daemon
            .delete_afc_channel(rpc_context(), self.local_channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// A unidirectional channel that can only receive.
#[derive(Clone)]
#[derive_where(Debug)]
pub struct ReceiveChannel {
    daemon: DaemonApiClient,
    keys: Arc<ChannelKeys>,
    channel_id: ChannelId,
    local_channel_id: AfcLocalChannelId,
    label_id: LabelId,
    peer_id: DeviceId,
    #[derive_where(skip(Debug))]
    open_ctx: Arc<Mutex<<ReadState<CS> as AfcState>::OpenCtx>>,
}

impl ReceiveChannel {
    /// The channel's unique ID.
    pub fn id(&self) -> ChannelId {
        self.channel_id
    }

    /// The channel's label ID.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// The device ID of the peer on the other side of the channel.
    pub fn peer_id(&self) -> DeviceId {
        self.peer_id
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
    ///
    /// Note: it is an error to invoke this method after the channel has been deleted.
    ///
    /// # Panics
    ///
    /// Will panic on poisoned internal mutexes.
    pub fn open(&self, dst: &mut [u8], ciphertext: &[u8]) -> Result<Seq, Error> {
        debug!(?self.local_channel_id, ?self.label_id, "open");
        let (label_id, seq) = self
            .keys
            .0
            .open(
                &mut *self.open_ctx.lock().expect("poisoned"),
                dst,
                ciphertext,
            )
            .map_err(AfcOpenError)
            .map_err(Error::Open)?;
        debug_assert_eq!(label_id.as_base(), self.label_id.into_api().as_base());
        Ok(Seq(seq))
    }

    /// Delete the channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.daemon
            .delete_afc_channel(rpc_context(), self.local_channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// Channel Keys.
pub(crate) struct ChannelKeys(AfcClient<ReadState<CS>>);

impl ChannelKeys {
    /// Open shared-memory client to daemon's channel key list.
    pub fn new(afc_shm_info: &AfcShmInfo) -> Result<Self, Error> {
        // TODO(#496): fix shm issue on some environments
        debug!(
            "setting up afc shm read side: {:?}",
            afc_shm_info.path.clone()
        );
        let read = ReadState::open(
            afc_shm_info.path.clone(),
            Flag::OpenOnly,
            Mode::ReadWrite,
            afc_shm_info.max_chans,
        )
        .with_context(|| format!("unable to open `ReadState`: {:?}", afc_shm_info.path))
        .map_err(Error::AfcIpc)?;

        Ok(Self(AfcClient::new(read)))
    }
}

impl Debug for ChannelKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelKeys").finish_non_exhaustive()
    }
}
