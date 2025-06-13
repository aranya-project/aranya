//! AQC support.

use std::net::SocketAddr;

use tarpc::context;
use tracing::{debug, instrument};

use super::{AqcBidiChannel, AqcPeerChannel, AqcSendChannel, TryReceiveError};
use crate::{
    client::{InvalidNetIdentifier, LabelId, NetIdentifier, TeamId},
    error::{aranya_error, no_addr, AqcError, IpcError},
    util::custom_id,
    Client,
};

custom_id! {
    /// Uniquely identifies a bidirectional AQC channel.
    pub struct AqcBidiChannelId;
}

custom_id! {
    /// Uniquely identifies a unidirectional AQC channel.
    pub struct AqcUniChannelId;
}

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
    pub fn client_addr(&self) -> Result<SocketAddr, AqcError> {
        Ok(self.client.aqc.client_addr()?)
    }

    /// Returns the address that the AQC server is bound to. This address is used by
    /// peers to connect to this instance.
    pub fn server_addr(&self) -> Result<SocketAddr, AqcError> {
        Ok(self.client.aqc.server_addr()?)
    }

    /// Creates a bidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// This method is NOT cancellation safe. Cancelling the resulting future might lose data.
    #[instrument(skip_all, fields(%team_id, %label_id))]
    pub async fn create_bidi_channel<'i, I>(
        &mut self,
        team_id: TeamId,
        peer: I,
        label_id: LabelId,
    ) -> crate::Result<AqcBidiChannel>
    where
        I: TryInto<NetIdentifier<'i>, Error = InvalidNetIdentifier>,
    {
        debug!("creating bidi channel");

        let peer: NetIdentifier<'i> = peer.try_into()?;

        let (aqc_ctrl, psks) = self
            .client
            .daemon
            .create_aqc_bidi_channel(
                context::current(),
                team_id.into_api(),
                peer.clone().into_api(),
                label_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, num_psks = psks.len(), "created bidi channel");

        let peer_addr = tokio::net::lookup_host(peer.as_ref())
            .await
            .map_err(AqcError::AddrResolution)?
            .next()
            .ok_or_else(no_addr)?;

        self.client
            .aqc
            .send_ctrl(peer_addr, aqc_ctrl, team_id.into_api())
            .await?;
        let channel = self
            .client
            .aqc
            .create_bidi_channel(peer_addr, label_id.into_api(), psks)
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
    #[instrument(skip_all, fields(%team_id, %label_id))]
    pub async fn create_uni_channel<'i, I>(
        &mut self,
        team_id: TeamId,
        peer: I,
        label_id: LabelId,
    ) -> crate::Result<AqcSendChannel>
    where
        I: TryInto<NetIdentifier<'i>, Error = InvalidNetIdentifier>,
    {
        debug!("creating aqc uni channel");

        let peer: NetIdentifier<'i> = peer.try_into()?;

        let (aqc_ctrl, psks) = self
            .client
            .daemon
            .create_aqc_uni_channel(
                context::current(),
                team_id.into_api(),
                peer.clone().into_api(),
                label_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, num_psks = psks.len(), "created uni channel");

        let peer_addr = tokio::net::lookup_host(peer.as_ref())
            .await
            .map_err(AqcError::AddrResolution)?
            .next()
            .ok_or_else(no_addr)?;

        self.client
            .aqc
            .send_ctrl(peer_addr, aqc_ctrl, team_id.into_api())
            .await?;

        let channel = self
            .client
            .aqc
            .create_uni_channel(peer_addr, label_id.into_api(), psks)
            .await?;
        Ok(channel)
    }

    /// Deletes an AQC bidi channel.
    #[instrument(skip_all, fields(?chan))]
    pub async fn delete_bidi_channel(&mut self, mut chan: AqcBidiChannel) -> crate::Result<()> {
        // let _ctrl = self
        //     .client
        //     .daemon
        //     .delete_aqc_bidi_channel(context::current(), chan.aqc_id().into_id().into())
        //     .await
        //     .map_err(IpcError::new)?
        //     .map_err(aranya_error)?;
        chan.close();
        Ok(())
    }

    /// Deletes an AQC uni channel.
    #[instrument(skip_all, fields(?chan))]
    pub async fn delete_uni_channel(&mut self, mut chan: AqcSendChannel) -> crate::Result<()> {
        // let _ctrl = self
        //     .client
        //     .daemon
        //     .delete_aqc_uni_channel(context::current(), chan.aqc_id().into_id().into())
        //     .await
        //     .map_err(IpcError::new)?
        //     .map_err(aranya_error)?;
        chan.close();
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
