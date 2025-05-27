//! AQC support.

use core::{fmt, net::SocketAddr};

use aranya_daemon_api::{AqcCtrl, AqcPsk};
use tarpc::context;
use tracing::{debug, instrument};

use crate::{
    client::{Client, InvalidNetIdentifier, LabelId, NetIdentifier, TeamId},
    error::{aranya_error, AqcError, IpcError, Result},
    util::custom_id,
};

custom_id! {
    /// An AQC bidi channel ID.
    pub struct BidiChannelId => AqcBidiChannelId;
}

custom_id! {
    /// An AQC uni channel ID.
    pub struct UniChannelId => AqcUniChannelId;
}

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
    #[instrument(skip(self))]
    pub async fn create_bidi_channel<I>(
        &mut self,
        team_id: TeamId,
        peer: I,
        label_id: LabelId,
    ) -> Result<BidiChannelId>
    where
        I: TryInto<NetIdentifier<'a>, Error = InvalidNetIdentifier> + fmt::Debug,
    {
        debug!("creating bidi channel");

        let (ctrl, psk) = self
            .client
            .daemon
            .create_aqc_bidi_channel(
                context::current(),
                team_id.into_api(),
                peer.try_into()?.into_api(),
                label_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, psk_ident = ?psk.identity, "created bidi channel");

        let chan_id = BidiChannelId::from_api(psk.identity.into());

        // TODO: send ctrl msg via network.
        let _ = ctrl;

        Ok(chan_id)
    }

    /// Creates a unidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip(self))]
    pub async fn create_uni_channel<I>(
        &mut self,
        team_id: TeamId,
        peer: I,
        label_id: LabelId,
    ) -> Result<UniChannelId>
    where
        I: TryInto<NetIdentifier<'a>, Error = InvalidNetIdentifier> + fmt::Debug,
    {
        debug!("creating aqc uni channel");

        let (ctrl, psk) = self
            .client
            .daemon
            .create_aqc_uni_channel(
                context::current(),
                team_id.into_api(),
                peer.try_into()?.into_api(),
                label_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        debug!(%label_id, psk_ident = ?psk.identity, "created bidi channel");

        let chan_id = UniChannelId::from_api(psk.identity.into());

        // TODO: send ctrl msg via network.
        let _ = ctrl;

        Ok(chan_id)
    }

    /// Deletes an AQC bidi channel.
    /// It is an error if the channel does not exist
    #[instrument(skip_all, fields(%chan))]
    pub async fn delete_bidi_channel(&mut self, chan: BidiChannelId) -> Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_aqc_bidi_channel(context::current(), chan.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        // TODO(geoff): implement this
        todo!()
    }

    /// Deletes an AQC uni channel.
    /// It is an error if the channel does not exist
    #[instrument(skip_all, fields(%chan))]
    pub async fn delete_uni_channel(&mut self, chan: UniChannelId) -> Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_aqc_uni_channel(context::current(), chan.into_api())
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
        let (_net_id, psk) = self
            .client
            .daemon
            .receive_aqc_ctrl(context::current(), team.into_api(), ctrl)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;

        match psk {
            AqcPsk::Bidi(psk) => {
                debug!(identity = ?psk.identity, "bidi psk identity");
            }
            AqcPsk::Uni(psk) => {
                debug!(identity = ?psk.identity, "uni psk identity");
            }
        }

        todo!()
    }
}
