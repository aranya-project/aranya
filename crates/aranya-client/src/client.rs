//! Client-daemon connection.

use std::{collections::VecDeque, net::SocketAddr, path::Path, time::Duration};

pub use aranya_daemon_api::AfcId;
use aranya_daemon_api::{DaemonApiClient, DeviceId, KeyBundle, NetIdentifier, Role, TeamId, CS};
use aranya_fast_channels::{self as afc, shm::ReadState, ChannelId};
pub use aranya_fast_channels::{Label, Seq};
use aranya_util::addr::Addr;
use tarpc::{context, tokio_serde::formats::Json};
use tokio::net::ToSocketAddrs;
use tracing::{debug, info, instrument};

use crate::{
    afc::{setup_afc_shm, Afc, Msg, State},
    Error, Result,
};

/// Data that can be polled by the AFC router.
#[must_use]
#[derive(Debug)]
pub struct PollData(State);

/// A client for invoking actions on and processing effects from
/// the Aranya graph.
///
/// `Client` interacts with the [Aranya daemon] via
/// [`aranya-daemon-api`] ([`tarpc`] over Unix domain sockets).
/// The client provides AFC functionality by interfacing with AFC
/// utilities in the Aranya core crates.
///
/// [Aranya daemon]: https://crates.io/crates/aranya-daemon
/// [`aranya-daemon-api`]: https://crates.io/crates/aranya-daemon-api
/// [`tarpc`]: https://crates.io/crates/tarpc
#[derive(Debug)]
pub struct Client {
    /// RPC connection to the daemon.
    daemon: DaemonApiClient,
    /// AFC support.
    afc: Afc<ReadState<CS>>,
    /// Messages from `handle_afc_data`.
    afc_msgs: VecDeque<AfcMsg>,
    #[cfg(feature = "debug")]
    name: String,
}

/// An Aranya Fast Channel message.
#[derive(Clone, Debug, PartialEq)]
pub struct AfcMsg {
    /// The plaintext data.
    pub data: Vec<u8>,
    /// The address from which the message was received.
    pub addr: SocketAddr,
    /// The channel from which the message was received.
    pub channel: AfcId,
    /// The Aranya Fast Channel label associated with the message.
    pub label: Label,
    /// The order of the message in the channel.
    pub seq: Seq,
}

impl Client {
    /// Creates a client connection to the daemon.
    ///
    /// - `daemon_sock`: The socket path to communicate with the
    ///   daemon.
    /// - `afc_shm_path`: AFC's shared memory path. The daemon
    ///   must also use the same path.
    /// - `max_chans`: The maximum number of channels that AFC
    ///   should support. The daemon must also use the same
    ///   number.
    /// - `afc_listen_addr`: The address that AFC listens for
    ///   incoming connections on.
    #[instrument(skip_all, fields(?daemon_sock, ?afc_shm_path, max_chans))]
    pub async fn connect<A>(
        daemon_sock: &Path,
        afc_shm_path: &Path,
        max_chans: usize,
        afc_listen_addr: A,
    ) -> Result<Self>
    where
        A: ToSocketAddrs,
    {
        info!("starting Aranya client");

        let transport = tarpc::serde_transport::unix::connect(daemon_sock, Json::default)
            .await
            .map_err(Error::Connecting)?;
        let daemon = DaemonApiClient::new(tarpc::client::Config::default(), transport).spawn();
        debug!("connected to daemon");

        let read = setup_afc_shm(afc_shm_path, max_chans)?;
        let afc = Afc::new(afc::Client::new(read), afc_listen_addr).await?;
        debug!(
            addr = ?afc.local_addr().map_err(Error::Afc)?,
            "bound AFC router",
        );
        Ok(Self {
            daemon,
            afc,
            afc_msgs: VecDeque::new(),
            #[cfg(feature = "debug")]
            name: String::new(),
        })
    }

    #[doc(hidden)]
    pub fn set_name(&mut self, _name: String) {
        #[cfg(feature = "debug")]
        {
            self.name = _name;
        }
    }

    #[cfg(feature = "debug")]
    fn debug(&self) -> &str {
        &self.name
    }

    #[cfg(not(feature = "debug"))]
    fn debug(&self) -> tracing::field::Empty {
        tracing::field::Empty
    }

    /// Returns the address that the Aranya sync server is bound
    /// to.
    pub async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.daemon.aranya_local_addr(context::current()).await??)
    }

    /// Returns the address that AFC is bound to.
    pub async fn afc_local_addr(&self) -> Result<SocketAddr> {
        self.afc.local_addr().map_err(Into::into)
    }

    /// Creates a bidirectional AFC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules
    /// that govern the channel. Both peers must already have
    /// permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so
    /// might lose data.
    #[instrument(skip_all, fields(self = self.debug(), %team_id, %peer, %label))]
    pub async fn create_afc_bidi_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label: Label,
    ) -> Result<AfcId> {
        debug!("creating bidi channel");

        let node_id = self.afc.get_next_node_id().await?;
        debug!(%node_id, "selected node ID");

        let (afc_id, ctrl) = self
            .daemon
            .create_afc_bidi_channel(context::current(), team_id, peer.clone(), node_id, label)
            .await??;
        debug!(%afc_id, %node_id, %label, "created bidi channel");

        let chan_id = ChannelId::new(node_id, label);
        self.afc
            .send_ctrl(peer, ctrl, team_id, afc_id, chan_id)
            .await?;
        debug!("sent control message");

        Ok(afc_id)
    }

    /// Deletes an AFC channel.
    // TODO(eric): Is it an error if the channel does not exist?
    #[instrument(skip_all, fields(self = self.debug(), afc_id = %id))]
    pub async fn delete_afc_channel(&mut self, id: AfcId) -> Result<()> {
        let _ctrl = self
            .daemon
            .delete_afc_channel(context::current(), id)
            .await??;
        self.afc.remove_channel(id).await;
        // TODO(eric): Send control message.
        // self.afc.send_ctrl(peer, ctrl, team_id, id, chan_id);
        Ok(())
    }

    /// Polls the client to check for new AFC data, then retrieves
    /// any new data.
    ///
    /// This is shorthand for [`poll_afc`][Self::poll_afc] and
    /// [`handle_afc_data`][Self::handle_afc_data].
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so
    /// might lose data.
    #[instrument(skip_all)]
    pub async fn poll_afc(&mut self) -> Result<()> {
        let data = self.poll_afc_data().await?;
        self.handle_afc_data(data).await
    }

    /// Polls the client to check for new AFC data.
    ///
    /// # Cancellation Safety
    ///
    /// It is safe to cancel the resulting future.
    #[instrument(skip_all)]
    pub async fn poll_afc_data(&mut self) -> Result<PollData> {
        let data = self.afc.poll().await?;
        Ok(PollData(data))
    }

    /// Retrieves AFC data from [`poll_afc`][Self::poll_afc].
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so
    /// might lose data.
    #[instrument(skip_all, fields(self = self.debug(), ?data))]
    pub async fn handle_afc_data(&mut self, data: PollData) -> Result<()> {
        match data.0 {
            State::Accept(addr) | State::Msg(addr) => match self.afc.read_msg(addr).await? {
                Msg::Data(data) => {
                    debug!(%addr, "read data message");

                    let (data, channel, label, seq) = self.afc.open_data(data)?;
                    self.afc_msgs.push_back(AfcMsg {
                        data,
                        addr,
                        channel,
                        label,
                        seq,
                    });
                    debug!(n = self.afc_msgs.len(), "stored msg");
                }
                Msg::Ctrl(ctrl) => {
                    debug!(%addr, "read control message");

                    let node_id = self.afc.get_next_node_id().await?;
                    debug!(%node_id, "selected node ID");

                    let (afc_id, peer, label) = self
                        .daemon
                        .receive_afc_ctrl(context::current(), ctrl.team_id, node_id, ctrl.cmd)
                        .await??;
                    debug!(%node_id, %label, "applied AFC control msg");

                    let chan_id = ChannelId::new(node_id, label);
                    self.afc
                        .add_channel(afc_id, peer, ctrl.team_id, chan_id, addr)
                        .await?;
                }
            },
        }
        Ok(())
    }

    /// Send AFC data over a specific fast channel.
    ///
    /// # Cancellation Safety
    ///
    /// It is safe to cancel the resulting future. However,
    /// a partial message may be written to the channel.
    // TODO(eric): Return a sequence number?
    #[instrument(skip_all, fields(self = self.debug(), afc_id = %id))]
    pub async fn send_afc_data(&mut self, id: AfcId, data: &[u8]) -> Result<()> {
        self.afc.send_data(id, data).await.map_err(Into::into)
    }

    /// Retrieves the next AFC message, if any.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so
    /// might lose data.
    // TODO: return [`NetIdentifier`] instead of [`SocketAddr`].
    // TODO: read into buffer instead of returning `Vec<u8>`.
    #[instrument(skip_all, fields(self = self.debug()))]
    pub fn try_recv_afc_data(&mut self) -> Option<AfcMsg> {
        // TODO(eric): This method should block until a message
        // has been received.
        let msg = self.afc_msgs.pop_front()?;
        debug!(label = %msg.label, seq = %msg.seq, "received AFC data message");
        Some(msg)
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
    pub async fn assign_afc_net_identifier(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        Ok(self
            .client
            .daemon
            .assign_afc_net_identifier(context::current(), self.id, device, net_identifier)
            .await??)
    }

    /// Disassociate an AFC network identifier from a device.
    pub async fn remove_afc_net_identifier(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        Ok(self
            .client
            .daemon
            .remove_afc_net_identifier(context::current(), self.id, device, net_identifier)
            .await??)
    }

    /// Associate a network identifier to a device for use with AQC.
    ///
    /// If the address already exists for this device, it is replaced with the new address. Capable
    /// of resolving addresses via DNS, required to be statically mapped to IPV4. For use with
    /// OpenChannel and receiving messages. Can take either DNS name or IPV4.
    pub async fn assign_aqc_net_identifier(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        Ok(self
            .client
            .daemon
            .assign_aqc_net_identifier(context::current(), self.id, device, net_identifier)
            .await??)
    }

    /// Disassociate an AQC network identifier from a device.
    pub async fn remove_aqc_net_identifier(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        Ok(self
            .client
            .daemon
            .remove_aqc_net_identifier(context::current(), self.id, device, net_identifier)
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

    /// Query devices on team.
    pub async fn query_devices_on_team(&mut self) -> Result<Vec<DeviceId>> {
        Ok(self
            .client
            .daemon
            .query_devices_on_team(context::current(), self.id)
            .await??)
    }

    /// Query device role.
    pub async fn query_device_role(&mut self, device: DeviceId) -> Result<Role> {
        Ok(self
            .client
            .daemon
            .query_device_role(context::current(), self.id, device)
            .await??)
    }

    /// Query device keybundle.
    pub async fn query_device_keybundle(&mut self, device: DeviceId) -> Result<KeyBundle> {
        Ok(self
            .client
            .daemon
            .query_device_keybundle(context::current(), self.id, device)
            .await??)
    }

    /// Query device label assignments.
    pub async fn query_device_label_assignments(&mut self, device: DeviceId) -> Result<Vec<Label>> {
        Ok(self
            .client
            .daemon
            .query_device_label_assignments(context::current(), self.id, device)
            .await??)
    }

    /// Query AFC network ID.
    pub async fn query_afc_net_identifier(&mut self, device: DeviceId) -> Result<NetIdentifier> {
        Ok(self
            .client
            .daemon
            .query_afc_net_identifier(context::current(), self.id, device)
            .await??)
    }

    /// Query AQC network ID.
    pub async fn query_aqc_net_identifier(&mut self, device: DeviceId) -> Result<NetIdentifier> {
        Ok(self
            .client
            .daemon
            .query_aqc_net_identifier(context::current(), self.id, device)
            .await??)
    }

    /// Query label exists.
    pub async fn query_label_exists(&mut self, label: Label) -> Result<bool> {
        Ok(self
            .client
            .daemon
            .query_label_exists(context::current(), self.id, label)
            .await??)
    }
}
