//! Client-daemon connection.

use std::{net::SocketAddr, path::Path};

#[cfg(feature = "afc")]
use aranya_daemon_api::CS;
use aranya_daemon_api::{DaemonApiClient, DeviceId, KeyBundle, NetIdentifier, Role, TeamId};
use aranya_fast_channels::Label;
#[cfg(feature = "afc")]
use aranya_fast_channels::{
    shm::ReadState,
    {self as afc},
};
use aranya_util::Addr;
use tarpc::{context, tokio_serde::formats::Json};
#[cfg(feature = "afc")]
use tokio::net::ToSocketAddrs;
use tracing::{debug, info, instrument};

#[cfg(feature = "afc")]
use crate::afc::{setup_afc_shm, FastChannels, FastChannelsImpl};
use crate::{
    config::{SyncPeerConfig, TeamConfig},
    error::{Error, Result},
};

/// List of device IDs.
pub struct Devices {
    data: Vec<DeviceId>,
}

impl Devices {
    pub fn iter(&self) -> impl Iterator<Item = &DeviceId> {
        self.data.iter()
    }

    #[doc(hidden)]
    pub fn __data(&self) -> &[DeviceId] {
        self.data.as_slice()
    }
}

/// List of labels.
pub struct Labels {
    pub data: Vec<Label>,
}

impl Labels {
    pub fn iter(&self) -> impl Iterator<Item = &Label> {
        self.data.iter()
    }

    #[doc(hidden)]
    pub fn __data(&self) -> &[Label] {
        self.data.as_slice()
    }
}

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
    /// RPC connection to the daemon
    pub(crate) daemon: DaemonApiClient,
    #[cfg(feature = "afc")]
    /// Support for Aranya Fast Channels
    pub(crate) afc: FastChannelsImpl<ReadState<CS>>,
}

impl Client {
    /// Creates a client connection to the daemon.
    ///
    /// - `daemon_socket`: The socket path to communicate with the daemon.
    /// - `afc_shm_path`: AFC's shared memory path. The daemon must also use the
    ///   same path.
    /// - `max_channels`: The maximum number of channels that AFC should support.
    ///   The daemon must also use the same number.
    /// - `afc_address`: The address that AFC listens for incoming connections
    ///   on.
    #[cfg(feature = "afc")]
    #[instrument(skip_all, fields(?daemon_socket, ?afc_shm_path, max_channels))]
    pub async fn connect<A>(
        daemon_socket: &Path,
        afc_shm_path: &Path,
        max_channels: usize,
        afc_address: A,
    ) -> Result<Self>
    where
        A: ToSocketAddrs,
    {
        info!("starting Aranya client");

        let transport = tarpc::serde_transport::unix::connect(daemon_socket, Json::default)
            .await
            .map_err(Error::Connecting)?;
        let daemon = DaemonApiClient::new(tarpc::client::Config::default(), transport).spawn();
        debug!("connected to daemon");

        let read = setup_afc_shm(afc_shm_path, max_channels)?;
        let afc = FastChannelsImpl::new(afc::Client::new(read), afc_address).await?;
        debug!(
            addr = ?afc.local_addr().map_err(Error::Afc)?,
            "bound AFC router",
        );

        Ok(Self { daemon, afc })
    }

    /// Creates a client connection to the daemon.
    ///
    /// - `daemon_socket`: The socket path to communicate with the daemon.
    #[cfg(not(feature = "afc"))]
    #[instrument(skip_all, fields(?daemon_socket))]
    pub async fn connect(daemon_socket: &Path) -> Result<Self> {
        info!("starting Aranya client");

        let transport = tarpc::serde_transport::unix::connect(daemon_socket, Json::default)
            .await
            .map_err(Error::Connecting)?;
        let daemon = DaemonApiClient::new(tarpc::client::Config::default(), transport).spawn();
        debug!("connected to daemon");

        Ok(Self { daemon })
    }

    /// Returns the address that the Aranya sync server is bound to.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        self.daemon
            .aranya_local_addr(context::current())
            .await?
            .map_err(Into::into)
    }

    /// Gets the public key bundle for this device.
    pub async fn get_key_bundle(&mut self) -> Result<KeyBundle> {
        self.daemon
            .get_key_bundle(context::current())
            .await?
            .map_err(Into::into)
    }

    /// Gets the public device ID for this device.
    pub async fn get_device_id(&mut self) -> Result<DeviceId> {
        self.daemon
            .get_device_id(context::current())
            .await?
            .map_err(Into::into)
    }

    /// Create a new graph/team with the current device as the owner.
    pub async fn create_team(&mut self, cfg: TeamConfig) -> Result<TeamId> {
        self.daemon
            .create_team(context::current(), cfg.into())
            .await?
            .map_err(Into::into)
    }

    /// Add a team to the local device store.
    pub async fn add_team(&mut self, team: TeamId, cfg: TeamConfig) -> Result<()> {
        self.daemon
            .add_team(context::current(), team, cfg.into())
            .await?
            .map_err(Into::into)
    }

    /// Remove a team from the local device store.
    pub async fn remove_team(&mut self, _team: TeamId) -> Result<()> {
        todo!()
    }

    /// Get an existing team.
    pub fn team(&mut self, id: TeamId) -> Team<'_> {
        Team { client: self, id }
    }

    #[cfg(feature = "afc")]
    /// Get access to Aranya Fast Channels.
    pub fn afc(&mut self) -> FastChannels<'_> {
        FastChannels::new(self)
    }

    /// Get access to fact database queries.
    pub fn queries(&mut self, id: TeamId) -> Queries<'_> {
        Queries { client: self, id }
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
    pub async fn add_sync_peer(&mut self, addr: Addr, config: SyncPeerConfig) -> Result<()> {
        self.client
            .daemon
            .add_sync_peer(context::current(), addr, self.id, config.into())
            .await?
            .map_err(Into::into)
    }

    /// Immediately syncs with the peer.
    ///
    /// If `config` is `None`, default values (including those from the daemon) will
    /// be used.
    pub async fn sync_now(&mut self, addr: Addr, cfg: Option<SyncPeerConfig>) -> Result<()> {
        self.client
            .daemon
            .sync_now(context::current(), addr, self.id, cfg.map(Into::into))
            .await?
            .map_err(Into::into)
    }

    /// Removes a peer from automatic Aranya state syncing.
    pub async fn remove_sync_peer(&mut self, addr: Addr) -> Result<()> {
        self.client
            .daemon
            .remove_sync_peer(context::current(), addr, self.id)
            .await?
            .map_err(Into::into)
    }

    /// Close the team and stop all operations on the graph.
    pub async fn close_team(&mut self) -> Result<()> {
        self.client
            .daemon
            .close_team(context::current(), self.id)
            .await?
            .map_err(Into::into)
    }

    /// Add a device to the team with the default `Member` role.
    pub async fn add_device_to_team(&mut self, keys: KeyBundle) -> Result<()> {
        self.client
            .daemon
            .add_device_to_team(context::current(), self.id, keys)
            .await?
            .map_err(Into::into)
    }

    /// Remove a device from the team.
    pub async fn remove_device_from_team(&mut self, device: DeviceId) -> Result<()> {
        self.client
            .daemon
            .remove_device_from_team(context::current(), self.id, device)
            .await?
            .map_err(Into::into)
    }

    /// Assign a role to a device.
    pub async fn assign_role(&mut self, device: DeviceId, role: Role) -> Result<()> {
        self.client
            .daemon
            .assign_role(context::current(), self.id, device, role)
            .await?
            .map_err(Into::into)
    }

    /// Revoke a role from a device. This sets the device's role back to the default `Member` role.
    pub async fn revoke_role(&mut self, device: DeviceId, role: Role) -> Result<()> {
        self.client
            .daemon
            .revoke_role(context::current(), self.id, device, role)
            .await?
            .map_err(Into::into)
    }

    /// Associate a network identifier to a device for use with AFC.
    ///
    /// If the address already exists for this device, it is replaced with the new address. Capable
    /// of resolving addresses via DNS, required to be statically mapped to IPV4. For use with
    /// OpenChannel and receiving messages. Can take either DNS name or IPV4.
    #[cfg(feature = "afc")]
    pub async fn assign_afc_net_identifier(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        self.client
            .daemon
            .assign_afc_net_identifier(context::current(), self.id, device, net_identifier)
            .await?
            .map_err(Into::into)
    }

    /// Disassociate an AFC network identifier from a device.
    #[cfg(feature = "afc")]
    pub async fn remove_afc_net_identifier(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        self.client
            .daemon
            .remove_afc_net_identifier(context::current(), self.id, device, net_identifier)
            .await?
            .map_err(Into::into)
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
        self.client
            .daemon
            .assign_aqc_net_identifier(context::current(), self.id, device, net_identifier)
            .await?
            .map_err(Into::into)
    }

    /// Disassociate an AQC network identifier from a device.
    pub async fn remove_aqc_net_identifier(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        self.client
            .daemon
            .remove_aqc_net_identifier(context::current(), self.id, device, net_identifier)
            .await?
            .map_err(Into::into)
    }

    /// Create an Aranya Fast Channels (AFC) label.
    pub async fn create_afc_label(&mut self, label: Label) -> Result<()> {
        self.client
            .daemon
            .create_afc_label(context::current(), self.id, label)
            .await?
            .map_err(Into::into)
    }

    /// Delete an Aranya Fast Channels (AFC) label.
    pub async fn delete_afc_label(&mut self, label: Label) -> Result<()> {
        self.client
            .daemon
            .delete_afc_label(context::current(), self.id, label)
            .await?
            .map_err(Into::into)
    }

    /// Assign an Aranya Fast Channels (AFC) label to a device.
    ///
    /// This grants the device permission to send/receive AFC data using that label.
    /// A channel must be created with the label in order to send data using that label.
    pub async fn assign_afc_label(&mut self, device: DeviceId, label: Label) -> Result<()> {
        self.client
            .daemon
            .assign_afc_label(context::current(), self.id, device, label)
            .await?
            .map_err(Into::into)
    }

    /// Revoke an Aranya Fast Channels (AFC) label from a device.
    pub async fn revoke_afc_label(&mut self, device: DeviceId, label: Label) -> Result<()> {
        self.client
            .daemon
            .revoke_afc_label(context::current(), self.id, device, label)
            .await?
            .map_err(Into::into)
    }
}

pub struct Queries<'a> {
    client: &'a mut Client,
    id: TeamId,
}

impl Queries<'_> {
    /// Returns the list of devices on the current team.
    pub async fn devices_on_team(&mut self) -> Result<Devices> {
        Ok(Devices {
            data: self
                .client
                .daemon
                .query_devices_on_team(context::current(), self.id)
                .await??,
        })
    }

    /// Returns the role of the current device.
    pub async fn device_role(&mut self, device: DeviceId) -> Result<Role> {
        self.client
            .daemon
            .query_device_role(context::current(), self.id, device)
            .await?
            .map_err(Into::into)
    }

    /// Returns the keybundle of the current device.
    pub async fn device_keybundle(&mut self, device: DeviceId) -> Result<KeyBundle> {
        self.client
            .daemon
            .query_device_keybundle(context::current(), self.id, device)
            .await?
            .map_err(Into::into)
    }

    /// Returns a list of labels assiged to the current device.
    pub async fn device_afc_label_assignments(&mut self, device: DeviceId) -> Result<Labels> {
        Ok(Labels {
            data: self
                .client
                .daemon
                .query_device_afc_label_assignments(context::current(), self.id, device)
                .await??,
        })
    }

    /// Returns the AFC network identifier assigned to the current device.
    #[cfg(feature = "afc")]
    pub async fn afc_net_identifier(&mut self, device: DeviceId) -> Result<Option<NetIdentifier>> {
        self.client
            .daemon
            .query_afc_net_identifier(context::current(), self.id, device)
            .await?
            .map_err(Into::into)
    }

    /// Returns the AQC network identifier assigned to the current device.
    pub async fn aqc_net_identifier(&mut self, device: DeviceId) -> Result<Option<NetIdentifier>> {
        self.client
            .daemon
            .query_aqc_net_identifier(context::current(), self.id, device)
            .await?
            .map_err(Into::into)
    }

    /// Returns whether a label exists.
    pub async fn afc_label_exists(&mut self, label: Label) -> Result<bool> {
        self.client
            .daemon
            .query_afc_label_exists(context::current(), self.id, label)
            .await?
            .map_err(Into::into)
    }
}
