//! AQC support.

pub use aranya_daemon_api::AqcId;
use aranya_daemon_api::{NetIdentifier, TeamId};
pub use aranya_fast_channels::Label;
use aranya_fast_channels::NodeId;
use tarpc::context;
use tracing::{debug, instrument};

use crate::error::AqcError;

/// Sends and receives AQC messages.
#[derive(Debug)]
pub(crate) struct AqcChannelsImpl {
    // TODO: add Aqc fields.
}

impl AqcChannelsImpl {
    /// Creates a new `FastChannelsImpl` listening for connections on `address`.
    pub(crate) async fn new() -> Result<Self, AqcError> {
        Ok(Self {})
    }
}

/// Aranya Fast Channels client that allows for opening and closing channels and
/// sending data between peers.
pub struct AqcChannels<'a> {
    client: &'a mut crate::Client,
}

impl<'a> AqcChannels<'a> {
    pub(crate) fn new(client: &'a mut crate::Client) -> Self {
        Self { client }
    }

    /// Creates a bidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label))]
    pub async fn create_bidi_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label: Label,
    ) -> crate::Result<AqcId> {
        debug!("creating bidi channel");

        let node_id: NodeId = 0.into();
        //let node_id = self.client.aqc.get_next_node_id().await?;
        debug!(%node_id, "selected node ID");

        let (aqc_id, _ctrl, _aqc_info) = self
            .client
            .daemon
            .create_aqc_bidi_channel(context::current(), team_id, peer.clone(), node_id, label)
            .await??;
        debug!(%aqc_id, %node_id, %label, "created bidi channel");

        Ok(aqc_id)
    }

    /// Creates a unidirectional AQC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all, fields(%team_id, %peer, %label))]
    pub async fn create_uni_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label: Label,
    ) -> crate::Result<AqcId> {
        debug!("creating aqc uni channel");

        // TODO: use correct node ID.
        let node_id: NodeId = 0.into();
        debug!(%node_id, "selected node ID");

        let (aqc_id, _ctrl, _aqc_info) = self
            .client
            .daemon
            .create_aqc_uni_channel(context::current(), team_id, peer.clone(), node_id, label)
            .await??;
        debug!(%aqc_id, %node_id, %label, "created aqc uni channel");

        // TODO: send ctrl message.
        debug!("sent control message");

        Ok(aqc_id)
    }

    /// Deletes an AQC channel.
    // TODO(eric): Is it an error if the channel does not exist?
    #[instrument(skip_all, fields(aqc_id = %id))]
    pub async fn delete_channel(&mut self, id: AqcId) -> crate::Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_aqc_channel(context::current(), id)
            .await??;
        //self.client.aqc.remove_channel(id).await;
        Ok(())
    }
}

// TODO: AQC shm.
// /// Setup the Aranya Client's read side of the AQC channel keys shared memory.
/*
pub(crate) fn setup_aqc_shm(shm_path: &Path, max_chans: usize) -> Result<ReadState<CS>, AqcError> {
    debug!(?shm_path, "setting up aqc shm read side");

    let Some(path) = shm_path.to_str() else {
        return Err(anyhow!("unable to convert shm path to string").into());
    };
    let path = ShmPathBuf::from_str(path).map_err(AqcError::ShmPathParse)?;
    let read = ReadState::open(&path, Flag::OpenOnly, Mode::ReadWrite, max_chans)
        .map_err(Into::into)
        .map_err(AqcError::ShmReadState)?;
    Ok(read)
}
*/
