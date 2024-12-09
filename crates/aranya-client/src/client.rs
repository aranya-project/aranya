//! Aranya Client Rust library.

use std::{collections::BTreeMap, net::SocketAddr, path::Path, str::FromStr, time::Duration};

use aranya_daemon_api::{
    AfcId, DaemonApiClient, DeviceId, KeyBundle, NetIdentifier, Role, TeamId, CS,
};
use aranya_fast_channels::{shm::ReadState, ChannelId, Label};
use aranya_util::addr::Addr;
use tarpc::{context, tokio_serde::formats::Json};
use tracing::{debug, info, instrument};

use crate::{
    afc::{setup_afc_shm, App, DataType, Router},
    Error, Result,
};

/// Data that can be polled by the AFC router.
#[must_use]
pub struct PollData(DataType);

/// Aranya client for invoking actions on and processing effects from the Aranya graph.
///
/// The Aranya client interacts with the `daemon` via the `aranya-daemon-api` unix domain socket `tarpc` API.
/// The client provides Aranya Fast Channels functionality by interfacing with Aranya Fast Channel utilities in the `aranya-core` repo.
pub struct Client {
    /// Client for interacting with the `aranya-daemon` process via the `aranya-daemon-api` API.
    daemon: DaemonApiClient,
    /// Aranya Fast Channels (AFC) data router.
    /// Encrypts plaintext based on AFC labels and sends it via the TCP transport.
    afc: Router<ReadState<CS>>,
    /// Application abstraction for sending/receiving data between the application and the AFC router.
    app: App,
    /// Aranya Fast Channel (AFC) channels.
    /// Keeps track of info for each channel.
    chans: BTreeMap<AfcId, (TeamId, NetIdentifier, Label)>,
}

/// An Aranya Fast Channel message.
pub struct AfcMsg {
    /// The plaintext data.
    pub data: Vec<u8>,
    /// The address from which the message was received.
    pub addr: SocketAddr,
    /// The channel from which the message was received.
    pub channel: AfcId,
    /// The Aranya Fast Channel label associated with the message.
    pub label: Label,
}

impl Client {
    /// Creates a client connected to the daemon.
    #[instrument(skip_all)]
    pub async fn connect(
        daemon_sock: &Path,
        afc_shm_path: &Path,
        max_chans: usize,
        afc_addr: Addr,
    ) -> Result<Self> {
        info!("starting Aranya client");
        info!("uds path: {:?}", daemon_sock);
        let transport = tarpc::serde_transport::unix::connect(daemon_sock, Json::default)
            .await
            .map_err(Error::Connecting)?;
        let daemon = DaemonApiClient::new(tarpc::client::Config::default(), transport).spawn();
        debug!("connected to: {:?}", daemon_sock);
        let read = setup_afc_shm(afc_shm_path, max_chans)?;
        let afc = aranya_fast_channels::Client::new(read);
        let (afc, app) = Router::new(afc, afc_addr).await.map_err(Error::AfcRouter)?;
        debug!(
            "afc router bound to: {:?}",
            afc.local_addr().map_err(Error::AfcRouter)?
        );
        Ok(Self {
            daemon,
            afc,
            app,
            chans: BTreeMap::new(),
        })
    }

    /// Returns address Aranya sync server bound to.
    pub async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.daemon.aranya_local_addr(context::current()).await??)
    }

    /// Returns address Aranya Fast Channels (AFC) server bound to.
    pub async fn afc_local_addr(&self) -> Result<SocketAddr> {
        self.afc.local_addr().map_err(Error::AfcRouter)
    }

    /// Creates a bidirectional Aranya Fast Channel (AFC).
    ///
    /// The device initiates creation of an Aranya Fast Channel with another peer.
    /// The channel is created using a specific label which means both peers must already have permission to use that label.
    /// During setup, an encrypted `ctrl` message is sent to the peer containing effects required to initialize the channel keys.
    /// When the peer receives the `ctrl` effects, it is able to configure a corresponding set of channel keys in order to perform `open`/`seal` operations for the channel.
    pub async fn create_bidi_channel(
        &mut self,
        team: TeamId,
        peer: NetIdentifier,
        label: Label,
    ) -> Result<AfcId> {
        debug!("creating AFC channel in Aranya");
        let node_id = self.afc.get_next_node_id().await?;
        let (afc_id, ctrl) = self
            .daemon
            .create_bidi_channel(context::current(), team, peer.clone(), node_id, label)
            .await??;
        debug!("creating AFC channel in AFC");
        // TODO: use existing mapping from `assign_net_identifier`
        let addr = Addr::from_str(&peer.0)
            .map_err(|_| Error::AfcRouter(crate::afc::AfcRouterError::AppWrite))?;
        let addr = addr
            .lookup()
            .await
            .map_err(|_| Error::AfcRouter(crate::afc::AfcRouterError::AppWrite))?;
        debug!(?label, ?team, ?addr, "sending ctrl msg");
        let channel_id = ChannelId::new(node_id, label);
        self.afc.insert_channel_id(afc_id, channel_id).await?;
        self.app.send_ctrl(SocketAddr::V4(addr), team, ctrl).await?;
        self.chans.insert(afc_id, (team, peer, label));
        debug!(?team, ?addr, ?label, "AFC channel created");
        Ok(afc_id)
    }

    /// Deletes an Aranya Fast Channel (AFC).
    pub async fn delete_channel(&mut self, chan: AfcId) -> Result<()> {
        let _ctrl = self
            .daemon
            .delete_channel(context::current(), chan)
            .await??;
        self.chans.remove(&chan);
        // TODO: delete AFC channel from AFC router.
        todo!()
    }

    /// Poll the Aranya Fast Channel router for new data and handle it.
    pub async fn poll(&mut self) -> Result<()> {
        let data = self.poll_data().await?;
        self.handle_data(data).await
    }

    /// Poll the Aranya Fast Channel router for new data.
    pub async fn poll_data(&mut self) -> Result<PollData> {
        #![allow(clippy::disallowed_macros)]
        let data = tokio::select! {
            biased;
            result = self.app.recv_ctrl() => result?,
            result = self.afc.poll() => result?,
        };
        Ok(PollData(data))
    }

    /// Handle any received data from the Aranya Fast Channel router.
    pub async fn handle_data(&mut self, data: PollData) -> Result<()> {
        match data.0 {
            DataType::Ctrl(ctrl) => {
                debug!("client lib received AFC ctrl msg");
                let node_id = ctrl.node_id;
                let (afc_id, net, label) = self
                    .daemon
                    .receive_afc_ctrl(context::current(), ctrl.team_id, node_id, ctrl.afc_ctrl)
                    .await??;
                let channel_id = ChannelId::new(node_id, label);
                self.afc.insert_channel_id(afc_id, channel_id).await?;
                self.chans.insert(afc_id, (ctrl.team_id, net, label));
            }
            _ => {
                self.afc.handle_data(data.0).await?;
            }
        }
        Ok(())
    }

    /// Send data via a specific Aranya Fast Channel.
    pub async fn send_data(&mut self, chan: AfcId, data: Vec<u8>) -> Result<()> {
        let (_team_id, peer, label) = self
            .chans
            .get(&chan)
            .ok_or(crate::afc::AfcRouterError::AppWrite)?;
        let addr = Addr::from_str(&peer.0).map_err(|_| crate::afc::AfcRouterError::AppWrite)?;
        let addr = addr
            .lookup()
            .await
            .map_err(|_| crate::afc::AfcRouterError::AppWrite)?;
        self.app
            .send_data(SocketAddr::V4(addr), *label, chan, data)
            .await?;
        Ok(())
    }

    /// Receive data from an Aranya Fast Channel.
    // TODO: return [`NetIdentifier`] instead of [`SocketAddr`].
    pub async fn recv_data(&mut self) -> Result<AfcMsg> {
        let (plaintext, addr, afc_id, label) = self.app.recv().await.map_err(Error::AfcRouter)?;
        debug!(n = plaintext.len(), "received AFC data message");
        Ok(AfcMsg {
            data: plaintext,
            addr,
            channel: afc_id,
            label,
        })
    }
}

impl Client {
    /// Gets the public key bundle for this device.
    pub async fn get_key_bundle(&mut self) -> Result<KeyBundle> {
        Ok(self.daemon.get_key_bundle(context::current()).await??)
    }

    /// Gets the public device ID for this device.
    pub async fn get_device_id(&mut self) -> Result<DeviceId> {
        Ok(self.daemon.get_device_id(context::current()).await??)
    }

    /// Create a new graph/team with the current device as the owner.
    pub async fn create_team(&mut self) -> Result<TeamId> {
        Ok(self.daemon.create_team(context::current()).await??)
    }

    /// Add a team to the local device store.
    pub async fn add_team(&mut self, team: TeamId) -> Result<()> {
        Ok(self.daemon.add_team(context::current(), team).await??)
    }

    /// Remove a team from the local device store.
    pub async fn remove_team(&mut self, _team: TeamId) -> Result<()> {
        todo!()
    }

    /// Get an existing team.
    pub fn team(&mut self, id: TeamId) -> Team<'_> {
        Team { client: self, id }
    }
}

/// Represents an Aranya Team.
///
/// The team allows a device to perform team related operations using the Aranya [`Client`].
/// These operations include:
/// - adding/removing sync peers.
/// - adding/removing devices from the team.
/// - assigning/revoking device roles.
/// - creating/assigning/deleting labels.
/// - creating/deleting fast channels.
/// - assigning network identifiers to devices.
pub struct Team<'a> {
    client: &'a mut Client,
    id: TeamId,
}

impl Team<'_> {
    /// Adds a peer for automatic periodic Aranya state syncing.
    pub async fn add_sync_peer(&mut self, addr: Addr, interval: Duration) -> Result<()> {
        Ok(self
            .client
            .daemon
            .add_sync_peer(context::current(), addr, self.id, interval)
            .await??)
    }

    /// Removes a peer from automatic Aranya state syncing.
    pub async fn remove_sync_peer(&mut self, addr: Addr) -> Result<()> {
        Ok(self
            .client
            .daemon
            .remove_sync_peer(context::current(), addr, self.id)
            .await??)
    }

    /// Close the team and stop all operations on the graph.
    pub async fn close_team(&mut self) -> Result<()> {
        Ok(self
            .client
            .daemon
            .close_team(context::current(), self.id)
            .await??)
    }

    /// Add a device to the team with the default `Member` role.
    pub async fn add_device_to_team(&mut self, keys: KeyBundle) -> Result<()> {
        Ok(self
            .client
            .daemon
            .add_device_to_team(context::current(), self.id, keys)
            .await??)
    }

    /// Remove a device from the team.
    pub async fn remove_device_from_team(&mut self, device: DeviceId) -> Result<()> {
        Ok(self
            .client
            .daemon
            .remove_device_from_team(context::current(), self.id, device)
            .await??)
    }

    /// Assign a role to a device.
    pub async fn assign_role(&mut self, device: DeviceId, role: Role) -> Result<()> {
        Ok(self
            .client
            .daemon
            .assign_role(context::current(), self.id, device, role)
            .await??)
    }

    /// Revoke a role from a device. This sets the device's role back to the default `Member` role.
    pub async fn revoke_role(&mut self, device: DeviceId, role: Role) -> Result<()> {
        Ok(self
            .client
            .daemon
            .revoke_role(context::current(), self.id, device, role)
            .await??)
    }

    /// Associate a network identifier to a device for use with AFC.
    ///
    /// If the address already exists for this device, it is replaced with the new address. Capable
    /// of resolving addresses via DNS, required to be statically mapped to IPV4. For use with
    /// OpenChannel and receiving messages. Can take either DNS name or IPV4.
    pub async fn assign_net_identifier(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        Ok(self
            .client
            .daemon
            .assign_net_identifier(context::current(), self.id, device, net_identifier)
            .await??)
    }

    /// Disassociate a network identifier from a device.
    pub async fn remove_net_identifier(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        Ok(self
            .client
            .daemon
            .remove_net_identifier(context::current(), self.id, device, net_identifier)
            .await??)
    }

    /// Create an Aranya Fast Channels (AFC) label.
    pub async fn create_label(&mut self, label: Label) -> Result<()> {
        Ok(self
            .client
            .daemon
            .create_label(context::current(), self.id, label)
            .await??)
    }

    /// Delete an Aranya Fast Channels (AFC) label.
    pub async fn delete_label(&mut self, label: Label) -> Result<()> {
        Ok(self
            .client
            .daemon
            .delete_label(context::current(), self.id, label)
            .await??)
    }

    /// Assign an Aranya Fast Channels (AFC) label to a device.
    ///
    /// This grants the device permission to send/receive AFC data using that label.
    /// A channel must be created with the label in order to send data using that label.
    pub async fn assign_label(&mut self, device: DeviceId, label: Label) -> Result<()> {
        Ok(self
            .client
            .daemon
            .assign_label(context::current(), self.id, device, label)
            .await??)
    }

    /// Revoke an Aranya Fast Channels (AFC) label from a device.
    pub async fn revoke_label(&mut self, device: DeviceId, label: Label) -> Result<()> {
        Ok(self
            .client
            .daemon
            .revoke_label(context::current(), self.id, device, label)
            .await??)
    }
}
