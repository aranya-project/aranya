//! AQC support.

use std::net::SocketAddr;

use buggy::BugExt;
use tarpc::context;
use tracing::{debug, instrument};

use crate::{
    aqc::{
        net::TryReceiveError, AqcBidiChannel, AqcPeerChannel, AqcReceiveChannel, AqcSendChannel,
    },
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
    client: &'a Client,
    aqc: &'a super::AqcClient,
}

impl<'a> AqcChannels<'a> {
    pub(crate) fn new(client: &'a Client) -> Option<Self> {
        Some(Self {
            client,
            aqc: client.aqc.as_ref()?,
        })
    }

    /// Returns the address that the AQC client is bound to. This address is used to
    /// make connections to other peers.
    pub fn client_addr(&self) -> SocketAddr {
        self.aqc.client_addr()
    }

    /// Returns the address that the AQC server is bound to. This address is used by
    /// peers to connect to this instance.
    pub fn server_addr(&self) -> SocketAddr {
        self.aqc.server_addr()
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
    pub async fn create_bidi_channel<I>(
        &mut self,
        team_id: TeamId,
        peer: I,
        label_id: LabelId,
    ) -> crate::Result<AqcBidiChannel>
    where
        I: TryInto<NetIdentifier>,
    {
        debug!("creating bidi channel");

        let peer: NetIdentifier = peer.try_into().map_err(|_| InvalidNetIdentifier(()))?;

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
            .as_ref()
            .assume("AQC is valid")?
            .send_ctrl(peer_addr, aqc_ctrl, team_id.into_api())
            .await?;
        let channel = self
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
    pub async fn create_uni_channel<I>(
        &mut self,
        team_id: TeamId,
        peer: I,
        label_id: LabelId,
    ) -> crate::Result<AqcSendChannel>
    where
        I: TryInto<NetIdentifier>,
    {
        debug!("creating aqc uni channel");

        let peer: NetIdentifier = peer.try_into().map_err(|_| InvalidNetIdentifier(()))?;

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
            .as_ref()
            .assume("AQC is valid")?
            .send_ctrl(peer_addr, aqc_ctrl, team_id.into_api())
            .await?;

        let channel = self
            .aqc
            .create_uni_channel(peer_addr, label_id.into_api(), psks)
            .await?;
        Ok(channel)
    }

    /// Deletes an AQC bidi channel.
    ///
    /// Zeroizes PSKs associated with the channel.
    /// Closes all associated QUIC connections and streams.
    #[instrument(skip_all, fields(aqc_id = %chan.aqc_id(), label = %chan.label_id()))]
    pub async fn delete_bidi_channel(&mut self, chan: &mut AqcBidiChannel) -> crate::Result<()> {
        chan.close();
        Ok(())
    }

    /// Deletes a send AQC uni channel.
    ///
    /// Zeroizes PSKs associated with the channel.
    /// Closes all associated QUIC connections and streams.
    #[instrument(skip_all, fields(aqc_id = %chan.aqc_id(), label = %chan.label_id()))]
    pub async fn delete_send_uni_channel(
        &mut self,
        chan: &mut AqcSendChannel,
    ) -> crate::Result<()> {
        chan.close();
        Ok(())
    }

    /// Deletes a receive AQC uni channel.
    ///
    /// Zeroizes PSKs associated with the channel.
    /// Closes all associated QUIC connections and streams.
    #[instrument(skip_all, fields(aqc_id = %chan.aqc_id(), label = %chan.label_id()))]
    pub async fn delete_receive_uni_channel(
        &mut self,
        chan: &mut AqcReceiveChannel,
    ) -> crate::Result<()> {
        chan.close();
        Ok(())
    }

    /// Waits for a peer to create an AQC channel with this client.
    #[instrument(skip_all)]
    pub async fn receive_channel(&self) -> crate::Result<AqcPeerChannel> {
        self.aqc.receive_channel().await
    }

    /// Receive the next available channel.
    ///
    /// If there is no channel available, return Empty.
    /// If the channel is closed, return Closed.
    #[instrument(skip_all)]
    pub fn try_receive_channel(&self) -> Result<AqcPeerChannel, TryReceiveError<crate::Error>> {
        self.aqc.try_receive_channel()
    }
}
