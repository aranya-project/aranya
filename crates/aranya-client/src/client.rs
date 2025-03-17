//! Client-daemon connection.

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use aranya_daemon_api::{DaemonApiClient, DeviceId, KeyBundle, NetIdentifier, Role, TeamId, CS};
use aranya_fast_channels::{
    shm::ReadState,
    Label, {self as afc},
};
use aranya_util::Addr;
use tarpc::{context, tokio_serde::formats::Json};
use tokio::net::ToSocketAddrs;
use tracing::{debug, info, instrument};

use crate::{
    afc::{setup_afc_shm, FastChannel},
    error::{Error, Result},
};

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
    daemon: Arc<DaemonApiClient>,
    /// AFC support.
    pub afc: FastChannel<ReadState<CS>>,
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
        let daemon =
            Arc::new(DaemonApiClient::new(tarpc::client::Config::default(), transport).spawn());
        debug!("connected to daemon");

        let read = setup_afc_shm(afc_shm_path, max_chans)?;
        let afc =
            FastChannel::new(afc::Client::new(read), Arc::clone(&daemon), afc_listen_addr).await?;
        debug!(
            addr = ?afc.local_addr().map_err(Error::Afc)?,
            "bound AFC router",
        );
        Ok(Self { daemon, afc })
    }

    /// Returns the address that the Aranya sync server is bound
    /// to.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.daemon.aranya_local_addr(context::current()).await??)
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

    /// Disassociate a network identifier from a device.
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
