//! AQC support.

use core::{fmt, net::SocketAddr};

pub use aranya_daemon_api::{AqcBidiChannelId, AqcUniChannelId};
use aranya_daemon_api::{AqcCtrl, AqcPsk, LabelId, NetIdentifier, TeamId};
use tarpc::context;
use tracing::{debug, instrument};

use crate::{
    error::{AqcError, IpcError},
    Result,
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
    client: &'a mut crate::Client,
}

impl<'a> AqcChannels<'a> {
    pub(crate) fn new(client: &'a mut crate::Client) -> Self {
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
    ) -> Result<(AqcBidiChannelId, AqcCtrl)> {
        debug!("creating bidi channel");

        let (ctrl, psk) = self
            .client
            .daemon
            .create_aqc_bidi_channel(context::current(), team_id, peer.clone(), label_id)
            .await
            .map_err(IpcError)??;
        debug!(%label_id, psk_ident = ?psk.identity, "created bidi channel");

        let chan_id = psk.identity;

        // TODO: send ctrl msg via network.

        Ok((chan_id.into(), ctrl))
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
    ) -> Result<(AqcUniChannelId, AqcCtrl)> {
        debug!("creating aqc uni channel");

        let (ctrl, psk) = self
            .client
            .daemon
            .create_aqc_uni_channel(context::current(), team_id, peer.clone(), label_id)
            .await
            .map_err(IpcError)??;
        debug!(%label_id, psk_ident = ?psk.identity, "created bidi channel");

        let chan_id = psk.identity;

        // TODO: send ctrl msg via network.

        Ok((chan_id.into(), ctrl))
    }

    /// Deletes an AQC bidi channel.
    // It is an error if the channel does not exist
    #[instrument(skip_all, fields(chan = %chan))]
    pub async fn delete_bidi_channel(&mut self, chan: AqcBidiChannelId) -> Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_aqc_bidi_channel(context::current(), chan)
            .await
            .map_err(IpcError)??;
        // TODO(geoff): implement this
        //self.client.aqc.remove_channel(chan).await;
        Ok(())
    }

    /// Deletes an AQC uni channel.
    // It is an error if the channel does not exist
    #[instrument(skip_all, fields(chan = %chan))]
    pub async fn delete_uni_channel(&mut self, chan: AqcUniChannelId) -> Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_aqc_uni_channel(context::current(), chan)
            .await
            .map_err(IpcError)??;
        // TODO(geoff): implement this
        //self.client.aqc.remove_channel(chan).await;
        Ok(())
    }

    /// Receives an AQC ctrl message.
    // TODO: this method is pub for testing.
    // In final AQC implementation, it will only be invoked when a ctrl msg is received via the network.
    pub async fn receive_aqc_ctrl(&mut self, team: TeamId, ctrl: AqcCtrl) -> Result<()> {
        let (_net_id, psk) = self
            .client
            .daemon
            .receive_aqc_ctrl(context::current(), team, ctrl)
            .await
            .map_err(IpcError)??;

        match psk {
            AqcPsk::Bidi(psk) => {
                debug!(identity = ?psk.identity, "bidi psk identity");
            }
            AqcPsk::Uni(psk) => {
                debug!(identity = ?psk.identity, "uni psk identity");
            }
        }

        Ok(())
    }
}
