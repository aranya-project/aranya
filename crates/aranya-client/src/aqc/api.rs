//! AQC support.

use std::net::SocketAddr;

use aranya_daemon_api::{LabelId, NetIdentifier, TeamId};
use tarpc::context;
use tracing::{debug, instrument};

use super::{net::TryReceiveError, AqcBidiChannel, AqcPeerChannel, AqcSendChannel};
use crate::{
    error::{aranya_error, no_addr, AqcError, IpcError},
    Client,
};

/// Aranya QUIC Channels client for managing channels which allow sending and
/// receiving data with peers.
#[derive(Debug)]
pub struct AqcChannels<'a> {
    client: &'a mut Client,
}

impl<'a> AqcChannels<'a> {
    pub(crate) fn new(client: &'a mut Client) -> Self {
        Self { client }
    }

    /// Returns the address that the AQC client is bound to. This address is used to
    /// make connections to other peers.
    pub fn client_addr(&self) -> SocketAddr {
        self.client.aqc.client_addr()
    }

    /// Returns the address that the AQC server is bound to. This address is used by
    /// peers to connect to this instance.
    pub fn server_addr(&self) -> SocketAddr {
        self.client.aqc.server_addr()
    }

    /// Creates a bidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// This method is NOT cancellation safe. Cancelling the resulting future might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label_id))]
    pub async fn create_bidi_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> crate::Result<AqcBidiChannel> {
        debug!("creating bidi channel");

        let (aqc_ctrl, psks) = self
            .client
            .daemon
            .create_aqc_bidi_channel(context::current(), team_id, peer.clone(), label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, num_psks = psks.len(), "created bidi channel");

        let peer_addr = tokio::net::lookup_host(peer.0.as_str())
            .await
            .map_err(AqcError::AddrResolution)?
            .next()
            .ok_or_else(no_addr)?;

        self.client
            .aqc
            .send_ctrl(peer_addr, aqc_ctrl, team_id)
            .await?;
        let channel = self
            .client
            .aqc
            .create_bidi_channel(peer_addr, label_id, psks)
            .await?;
        Ok(channel)
    }

    /// Creates a unidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// This method is NOT cancellation safe. Cancelling the resulting future might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label_id))]
    pub async fn create_uni_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> crate::Result<AqcSendChannel> {
        debug!("creating aqc uni channel");

        let (aqc_ctrl, psks) = self
            .client
            .daemon
            .create_aqc_uni_channel(context::current(), team_id, peer.clone(), label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, num_psks = psks.len(), "created uni channel");

        let peer_addr = tokio::net::lookup_host(peer.0.as_str())
            .await
            .map_err(AqcError::AddrResolution)?
            .next()
            .ok_or_else(no_addr)?;

        self.client
            .aqc
            .send_ctrl(peer_addr, aqc_ctrl, team_id)
            .await?;

        let channel = self
            .client
            .aqc
            .create_uni_channel(peer_addr, label_id, psks)
            .await?;
        Ok(channel)
    }

    /// Deletes an AQC bidi channel.
    #[instrument(skip_all, fields(?chan))]
    pub async fn delete_bidi_channel(&mut self, chan: AqcBidiChannel) -> crate::Result<()> {
        self.client.aqc.delete_bidi_channel(chan).await;
        Ok(())
    }

    /// Deletes an AQC uni channel.
    #[instrument(skip_all, fields(?chan))]
    pub async fn delete_uni_channel(&mut self, chan: AqcSendChannel) -> crate::Result<()> {
        self.client.aqc.delete_uni_channel(chan).await;
        Ok(())
    }

    /// Waits for a peer to create an AQC channel with this client.
    pub async fn receive_channel(&mut self) -> crate::Result<AqcPeerChannel> {
        self.client.aqc.receive_channel().await
    }

    /// Receive the next available channel.
    ///
    /// If there is no channel available, return Empty.
    /// If the channel is closed, return Closed.
    pub fn try_receive_channel(&mut self) -> Result<AqcPeerChannel, TryReceiveError<crate::Error>> {
        self.client.aqc.try_receive_channel()
    }
}
