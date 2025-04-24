//! Client-daemon connection.

use core::net::SocketAddr;
use std::{io, path::Path};

use aranya_crypto::Rng;
use aranya_daemon_api::{
    crypto::{
        txp::{self, LengthDelimitedCodec},
        PublicApiKey,
    },
    ChanOp, DaemonApiClient, DeviceId, KeyBundle, Label, LabelId, NetIdentifier, Role, TeamId,
    Version, CS,
};
use aranya_util::Addr;
use tarpc::context;
use tokio::net::UnixStream;
use tracing::{debug, info, instrument};

use crate::{
    aqc::{AqcChannels, AqcChannelsImpl},
    config::{SyncPeerConfig, TeamConfig},
    error::{aranya_error, InvalidArg, IpcError, Result},
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
    data: Vec<Label>,
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

/// Builds a [`Client`].
pub struct ClientBuilder<'a> {
    /// The UDS that the daemon is listening on.
    #[cfg(unix)]
    uds_path: Option<&'a Path>,
    // The daemon's public key.
    pk: Option<&'a [u8]>,
}

impl ClientBuilder<'_> {
    fn new() -> Self {
        Self {
            uds_path: None,
            pk: None,
        }
    }

    /// Connects to the daemon.
    pub async fn connect(self) -> Result<Client> {
        let Some(sock) = self.uds_path else {
            return Err(IpcError::new(InvalidArg::new(
                "with_daemon_uds_path",
                "must specify the daemon's UDS path",
            ))
            .into());
        };
        let Some(pk) = &self.pk else {
            return Err(IpcError::new(InvalidArg::new(
                "with_daemon_api_pk",
                "must specify the daemon's public key",
            ))
            .into());
        };
        Client::connect(sock, pk).await
    }
}

impl<'a> ClientBuilder<'a> {
    /// Specifies the UDS socket path the daemon is listening on.
    #[cfg(unix)]
    #[cfg_attr(docsrs, doc(cfg(unix)))]
    pub fn with_daemon_uds_path(mut self, sock: &'a Path) -> Self {
        self.uds_path = Some(sock);
        self
    }

    /// Specifies the daemon's public API key.
    pub fn with_daemon_api_pk(mut self, pk: &'a [u8]) -> Self {
        self.pk = Some(pk);
        self
    }
}

/// A client for invoking actions on and processing effects from
/// the Aranya graph.
///
/// `Client` interacts with the [Aranya daemon] over
/// a platform-specific IPC mechanism.
///
/// [Aranya daemon]: https://crates.io/crates/aranya-daemon
#[derive(Debug)]
pub struct Client {
    /// RPC connection to the daemon
    pub(crate) daemon: DaemonApiClient,
    /// Support for AQC
    pub(crate) _aqc: AqcChannelsImpl,
}

impl Client {
    /// Returns a builder for `Client`.
    pub fn builder<'a>() -> ClientBuilder<'a> {
        ClientBuilder::new()
    }

    /// Creates a client connection to the daemon.
    #[instrument(skip_all, fields(?path))]
    async fn connect(path: &Path, pk: &[u8]) -> Result<Self> {
        info!("starting Aranya client");

        let sock = UnixStream::connect(path).await.map_err(IpcError::new)?;
        let pk = PublicApiKey::<CS>::decode(pk)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
            .map_err(IpcError::new)?;
        let info = path.as_os_str().as_encoded_bytes();
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(usize::MAX)
            .new_codec();
        let transport = txp::client(sock, codec, Rng, pk, info);

        let daemon = DaemonApiClient::new(tarpc::client::Config::default(), transport).spawn();
        debug!("connected to daemon");

        let got = daemon
            .version(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        let want = Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
            .map_err(IpcError::new)?;
        if got.major != want.major || got.minor != want.minor {
            return Err(IpcError::new(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("version mismatch: `{got}` != `{want}`"),
            ))
            .into());
        }
        debug!(client = ?want, daemon = ?got, "versions");

        let aqc = AqcChannelsImpl::new().await?;

        Ok(Self { daemon, _aqc: aqc })
    }

    /// Returns the address that the Aranya sync server is bound to.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        self.daemon
            .aranya_local_addr(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Gets the public key bundle for this device.
    pub async fn get_key_bundle(&mut self) -> Result<KeyBundle> {
        self.daemon
            .get_key_bundle(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Gets the public device ID for this device.
    pub async fn get_device_id(&mut self) -> Result<DeviceId> {
        self.daemon
            .get_device_id(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Create a new graph/team with the current device as the owner.
    pub async fn create_team(&mut self, cfg: TeamConfig) -> Result<TeamId> {
        self.daemon
            .create_team(context::current(), cfg.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Add a team to the local device store.
    pub async fn add_team(&mut self, team: TeamId, cfg: TeamConfig) -> Result<()> {
        self.daemon
            .add_team(context::current(), team, cfg.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Remove a team from the local device store.
    pub async fn remove_team(&mut self, _team: TeamId) -> Result<()> {
        todo!()
    }

    /// Get an existing team.
    pub fn team(&mut self, id: TeamId) -> Team<'_> {
        Team { client: self, id }
    }

    /// Get access to Aranya QUIC Channels.
    pub fn aqc(&mut self) -> AqcChannels<'_> {
        AqcChannels::new(self)
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
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Immediately syncs with the peer.
    ///
    /// If `config` is `None`, default values (including those from the daemon) will
    /// be used.
    pub async fn sync_now(&mut self, addr: Addr, cfg: Option<SyncPeerConfig>) -> Result<()> {
        self.client
            .daemon
            .sync_now(context::current(), addr, self.id, cfg.map(Into::into))
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes a peer from automatic Aranya state syncing.
    pub async fn remove_sync_peer(&mut self, addr: Addr) -> Result<()> {
        self.client
            .daemon
            .remove_sync_peer(context::current(), addr, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Close the team and stop all operations on the graph.
    pub async fn close_team(&mut self) -> Result<()> {
        self.client
            .daemon
            .close_team(context::current(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Add a device to the team with the default `Member` role.
    pub async fn add_device_to_team(&mut self, keys: KeyBundle) -> Result<()> {
        self.client
            .daemon
            .add_device_to_team(context::current(), self.id, keys)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Remove a device from the team.
    pub async fn remove_device_from_team(&mut self, device: DeviceId) -> Result<()> {
        self.client
            .daemon
            .remove_device_from_team(context::current(), self.id, device)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Assign a role to a device.
    pub async fn assign_role(&mut self, device: DeviceId, role: Role) -> Result<()> {
        self.client
            .daemon
            .assign_role(context::current(), self.id, device, role)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revoke a role from a device. This sets the device's role back to the default `Member` role.
    pub async fn revoke_role(&mut self, device: DeviceId, role: Role) -> Result<()> {
        self.client
            .daemon
            .revoke_role(context::current(), self.id, device, role)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
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
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
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
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Create a label.
    pub async fn create_label(&mut self, label_name: String) -> Result<LabelId> {
        self.client
            .daemon
            .create_label(context::current(), self.id, label_name)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Delete a label.
    pub async fn delete_label(&mut self, label_id: LabelId) -> Result<()> {
        self.client
            .daemon
            .delete_label(context::current(), self.id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Assign a label to a device.
    pub async fn assign_label(
        &mut self,
        device: DeviceId,
        label_id: LabelId,
        op: ChanOp,
    ) -> Result<()> {
        self.client
            .daemon
            .assign_label(context::current(), self.id, device, label_id, op)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revoke a label from a device.
    pub async fn revoke_label(&mut self, device: DeviceId, label_id: LabelId) -> Result<()> {
        self.client
            .daemon
            .revoke_label(context::current(), self.id, device, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}

pub struct Queries<'a> {
    client: &'a mut Client,
    id: TeamId,
}

impl Queries<'_> {
    /// Returns the list of devices on the current team.
    pub async fn devices_on_team(&mut self) -> Result<Devices> {
        let data = self
            .client
            .daemon
            .query_devices_on_team(context::current(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Devices { data })
    }

    /// Returns the role of the current device.
    pub async fn device_role(&mut self, device: DeviceId) -> Result<Role> {
        self.client
            .daemon
            .query_device_role(context::current(), self.id, device)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns the keybundle of the current device.
    pub async fn device_keybundle(&mut self, device: DeviceId) -> Result<KeyBundle> {
        self.client
            .daemon
            .query_device_keybundle(context::current(), self.id, device)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns a list of labels assiged to the current device.
    pub async fn device_label_assignments(&mut self, device: DeviceId) -> Result<Labels> {
        let data = self
            .client
            .daemon
            .query_device_label_assignments(context::current(), self.id, device)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Labels { data })
    }

    /// Returns the AQC network identifier assigned to the current device.
    pub async fn aqc_net_identifier(&mut self, device: DeviceId) -> Result<Option<NetIdentifier>> {
        self.client
            .daemon
            .query_aqc_net_identifier(context::current(), self.id, device)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns whether a label exists.
    pub async fn label_exists(&mut self, label_id: LabelId) -> Result<bool> {
        self.client
            .daemon
            .query_label_exists(context::current(), self.id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns a list of labels on the team.
    pub async fn labels(&mut self) -> Result<Labels> {
        let data = self
            .client
            .daemon
            .query_labels(context::current(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Labels { data })
    }
}
