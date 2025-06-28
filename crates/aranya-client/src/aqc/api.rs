//! AQC support.

use std::{net::SocketAddr, sync::Arc};

use aranya_daemon_api::{DaemonApiClient, LabelId, NetIdentifier, TeamId};
use tarpc::context;
use tokio::sync::Mutex;
use tracing::{debug, instrument};

use super::{net::TryReceiveError, AqcBidiChannel, AqcPeerChannel, AqcSendChannel};
use crate::{
    aqc::AqcClient,
    error::{aranya_error, no_addr, AqcError, IpcError},
};

/// Aranya QUIC Channels client for managing channels which allow sending and
/// receiving data with peers.
#[derive(Debug)]
pub struct AqcChannels {
    daemon: Arc<Mutex<DaemonApiClient>>,
    aqc: Arc<Mutex<AqcClient>>,
}

impl AqcChannels {
    pub(crate) fn new(daemon: Arc<Mutex<DaemonApiClient>>, aqc: Arc<Mutex<AqcClient>>) -> Self {
        Self { daemon, aqc }
    }

    /// Returns the address that the AQC client is bound to. This address is used to
    /// make connections to other peers.
    pub async fn client_addr(&self) -> Result<SocketAddr, AqcError> {
        Ok(self.aqc.lock().await.client_addr()?)
    }

    /// Returns the address that the AQC server is bound to. This address is used by
    /// peers to connect to this instance.
    pub async fn server_addr(&self) -> Result<SocketAddr, AqcError> {
        Ok(self.aqc.lock().await.server_addr()?)
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
            .daemon
            .lock()
            .await
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

        self.aqc
            .lock()
            .await
            .send_ctrl(peer_addr, aqc_ctrl, team_id)
            .await?;
        let channel = self
            .aqc
            .lock()
            .await
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
            .daemon
            .lock()
            .await
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

        self.aqc
            .lock()
            .await
            .send_ctrl(peer_addr, aqc_ctrl, team_id)
            .await?;

        let channel = self
            .aqc
            .lock()
            .await
            .create_uni_channel(peer_addr, label_id, psks)
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
        self.aqc.lock().await.receive_channel().await
    }

    /// Receive the next available channel.
    ///
    /// If there is no channel available, return Empty.
    /// If the channel is closed, return Closed.
    pub async fn try_receive_channel(
        &mut self,
    ) -> Result<AqcPeerChannel, TryReceiveError<crate::Error>> {
        self.aqc.lock().await.try_receive_channel()
    }
}
