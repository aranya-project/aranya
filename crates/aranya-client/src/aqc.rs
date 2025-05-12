//! AQC support.

use core::{fmt, net::SocketAddr};

pub use aranya_daemon_api::{AqcBidiChannelId, AqcUniChannelId};
use aranya_daemon_api::{AqcCtrl, AqcPsk, LabelId, NetIdentifier, TeamId};
use tarpc::context;
use tracing::{debug, instrument};

use crate::{
    error::{aranya_error, AqcError, IpcError},
    Client, Result,
};

/// Sends and receives AQC messages.
pub(crate) struct AqcChannelsImpl {}

impl AqcChannelsImpl {
    /// Creates a new `AqcChannelsImpl` listening for connections on `address`.
    #[instrument(skip_all)]
    pub(crate) async fn new() -> Result<Self, AqcError> {
        Ok(Self {})
    }
}

impl fmt::Debug for AqcChannelsImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AqcChannelsImpl").finish_non_exhaustive()
    }
}

/// Aranya QUIC Channels client that allows for opening and closing channels and
/// sending data between peers.
#[derive(Debug)]
pub struct AqcChannels<'a> {
    client: &'a mut Client,
}

impl<'a> AqcChannels<'a> {
    pub(crate) fn new(client: &'a mut Client) -> Self {
        Self { client }
    }

    /// Returns the address that AQC is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, AqcError> {
        todo!()
    }

    /// Creates a bidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label_id))]
    pub async fn create_bidi_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> Result<AqcBidiChannelId> {
        debug!("creating bidi channel");

        let (ctrl, psks) = self
            .client
            .daemon
            .create_aqc_bidi_channel(context::current(), team_id, peer.clone(), label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, num_psks = psks.len(), "created bidi channel");

        let chan_id = *psks[0].identity.channel_id();

        // TODO: send ctrl msg via network.
        let _ = ctrl;

        Ok(chan_id.into_id().into())
    }

    /// Creates a unidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label_id))]
    pub async fn create_uni_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> Result<AqcUniChannelId> {
        debug!("creating aqc uni channel");

        let (ctrl, psks) = self
            .client
            .daemon
            .create_aqc_uni_channel(context::current(), team_id, peer.clone(), label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, num_psks = psks.len(), "created bidi channel");

        let chan_id = *psks[0].identity.channel_id();

        // TODO: send ctrl msg via network.
        let _ = ctrl;

        Ok(chan_id.into_id().into())
    }

    /// Deletes an AQC bidi channel.
    /// It is an error if the channel does not exist
    #[instrument(skip_all, fields(%chan))]
    pub async fn delete_bidi_channel(&mut self, chan: AqcBidiChannelId) -> Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_aqc_bidi_channel(context::current(), chan)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        // TODO(geoff): implement this
        todo!()
    }

    /// Deletes an AQC uni channel.
    /// It is an error if the channel does not exist
    #[instrument(skip_all, fields(%chan))]
    pub async fn delete_uni_channel(&mut self, chan: AqcUniChannelId) -> Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_aqc_uni_channel(context::current(), chan)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        // TODO(geoff): implement this
        todo!()
    }

    /// Receives an AQC ctrl message.
    // TODO: this method is pub for testing.
    // In final AQC implementation, it will only be invoked when a ctrl msg is received via the network.
    #[instrument(skip_all, fields(%team))]
    async fn receive_aqc_ctrl(&mut self, team: TeamId, ctrl: AqcCtrl) -> Result<()> {
        let (_net_id, psks) = self
            .client
            .daemon
            .receive_aqc_ctrl(context::current(), team, ctrl)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;

        for psk in psks {
            match psk {
                AqcPsk::Bidi(psk) => {
                    debug!(identity = ?psk.identity, "bidi psk identity");
                }
                AqcPsk::Uni(psk) => {
                    debug!(identity = ?psk.identity, "uni psk identity");
                }
            }
        }

        todo!()
    }
}
