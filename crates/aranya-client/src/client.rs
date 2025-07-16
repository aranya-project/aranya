//! Client-daemon connection.

use std::{io, net::SocketAddr, path::Path};

use anyhow::Context as _;
use aranya_crypto::{Csprng, EncryptionPublicKey, Rng};
use aranya_daemon_api::{
    crypto::{
        txp::{self, LengthDelimitedCodec},
        PublicApiKey,
    },
    ChanOp, DaemonApiClient, DeviceId, KeyBundle, Label, LabelId, NetIdentifier, Role, TeamId,
    Text, Version, CS,
};
use aranya_util::{error::ReportExt as _, Addr};
use buggy::BugExt as _;
use tarpc::context;
use tokio::{fs, net::UnixStream};
use tracing::{debug, error, info, instrument};

use crate::{
    aqc::{AqcChannels, AqcClient},
    config::{AddTeamConfig, CreateTeamConfig, SyncPeerConfig},
    error::{self, aranya_error, InvalidArg, IpcError, Result},
};

/// List of device IDs.
#[derive(Debug)]
pub struct Devices {
    data: Vec<DeviceId>,
}

impl Devices {
    /// Return iterator for list of devices.
    pub fn iter(&self) -> impl Iterator<Item = &DeviceId> {
        self.data.iter()
    }

    #[doc(hidden)]
    pub fn __data(&self) -> &[DeviceId] {
        self.data.as_slice()
    }
}

/// List of labels.
#[derive(Debug)]
pub struct Labels {
    data: Vec<Label>,
}

impl Labels {
    /// Return iterator for list of labels.
    pub fn iter(&self) -> impl Iterator<Item = &Label> {
        self.data.iter()
    }

    #[doc(hidden)]
    pub fn __data(&self) -> &[Label] {
        self.data.as_slice()
    }
}

/// Builds a [`Client`].
#[derive(Debug, Default)]
pub struct ClientBuilder<'a> {
    /// The UDS that the daemon is listening on.
    #[cfg(unix)]
    daemon_uds_path: Option<&'a Path>,
    // AQC address.
    aqc_server_addr: Option<&'a Addr>,
}

impl ClientBuilder<'_> {
    /// Returns a default [`ClientBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Connects to the daemon.
    pub async fn connect(self) -> Result<Client> {
        let Some(sock) = self.daemon_uds_path else {
            return Err(IpcError::new(InvalidArg::new(
                "daemon_uds_path",
                "must specify the daemon's UDS path",
            ))
            .into());
        };

        let Some(aqc_addr) = &self.aqc_server_addr else {
            return Err(IpcError::new(InvalidArg::new(
                "aqc_server_addr",
                "must specify the AQC server address",
            ))
            .into());
        };
        Client::connect(sock, aqc_addr)
            .await
            .inspect_err(|err| error!(error = %err.report(), "unable to connect to daemon"))
    }
}

impl<'a> ClientBuilder<'a> {
    /// Specifies the UDS socket path the daemon is listening on.
    #[cfg(unix)]
    #[cfg_attr(docsrs, doc(cfg(unix)))]
    pub fn daemon_uds_path(mut self, sock: &'a Path) -> Self {
        self.daemon_uds_path = Some(sock);
        self
    }

    /// Specifies the AQC server address.
    pub fn aqc_server_addr(mut self, addr: &'a Addr) -> Self {
        self.aqc_server_addr = Some(addr);
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
    pub(crate) aqc: AqcClient,
}

impl Client {
    /// Returns a builder for `Client`.
    pub fn builder<'a>() -> ClientBuilder<'a> {
        ClientBuilder::new()
    }

    /// Creates a client connection to the daemon.
    #[instrument(skip_all)]
    async fn connect(uds_path: &Path, aqc_addr: &Addr) -> Result<Self> {
        info!(path = ?uds_path, "connecting to daemon");

        let daemon = {
            let pk = {
                // The public key is located next to the socket.
                let api_pk_path = uds_path.parent().unwrap_or(uds_path).join("api.pk");
                let bytes = fs::read(&api_pk_path)
                    .await
                    .with_context(|| "unable to read daemon API public key")
                    .map_err(IpcError::new)?;
                PublicApiKey::<CS>::decode(&bytes)
                    .context("unable to decode public API key")
                    .map_err(IpcError::new)?
            };

            let sock = UnixStream::connect(uds_path)
                .await
                .context("unable to connect to UDS path")
                .map_err(IpcError::new)?;
            let info = uds_path.as_os_str().as_encoded_bytes();
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(usize::MAX)
                .new_codec();
            let transport = txp::client(sock, codec, Rng, pk, info);

            DaemonApiClient::new(tarpc::client::Config::default(), transport).spawn()
        };
        debug!("connected to daemon");

        let got = daemon
            .version(context::current())
            .await
            .map_err(IpcError::new)?
            .context("unable to retrieve daemon version")
            .map_err(error::other)?;
        let want = Version::parse(env!("CARGO_PKG_VERSION"))
            .context("unable to parse `CARGO_PKG_VERSION`")
            .map_err(error::other)?;
        if got.major != want.major || got.minor != want.minor {
            return Err(IpcError::new(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("version mismatch: `{got}` != `{want}`"),
            ))
            .into());
        }
        debug!(client = ?want, daemon = ?got, "versions");

        let aqc_server_addr = aqc_addr
            .lookup()
            .await
            .context("unable to resolve AQC server address")
            .map_err(error::other)?
            .next()
            .expect("expected AQC server address");
        let aqc = AqcClient::new(aqc_server_addr, daemon.clone()).await?;
        let client = Self { daemon, aqc };

        Ok(client)
    }

    /// Returns the address that the Aranya sync server is bound to.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        self.daemon
            .aranya_local_addr(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns the address that the AQC client is bound to.
    pub async fn aqc_client_addr(&self) -> Result<SocketAddr> {
        Ok(self.aqc.client_addr()) // TODO: Remove error?
    }

    /// Gets the public key bundle for this device.
    pub async fn get_key_bundle(&self) -> Result<KeyBundle> {
        self.daemon
            .get_key_bundle(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Gets the public device ID for this device.
    pub async fn get_device_id(&self) -> Result<DeviceId> {
        self.daemon
            .get_device_id(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Create a new graph/team with the current device as the owner.
    pub async fn create_team(&self, cfg: CreateTeamConfig) -> Result<Team<'_>> {
        let team_id = self
            .daemon
            .create_team(context::current(), cfg.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Team {
            client: self,
            team_id,
        })
    }

    /// Generate random bytes from a CSPRNG.
    /// Can be used to generate IKM for a generating a PSK seed.
    pub async fn rand(&self, buf: &mut [u8]) {
        <Rng as Csprng>::fill_bytes(&mut Rng, buf);
    }

    /// Get an existing team.
    pub fn team(&self, team_id: TeamId) -> Team<'_> {
        Team {
            client: self,
            team_id,
        }
    }

    /// Add a team to local device storage.
    pub async fn add_team(&self, cfg: AddTeamConfig) -> Result<Team<'_>> {
        let cfg = aranya_daemon_api::AddTeamConfig::from(cfg);
        let team_id = cfg.team_id;

        self.daemon
            .add_team(context::current(), cfg)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Team {
            client: self,
            team_id,
        })
    }

    /// Remove a team from local device storage.
    pub async fn remove_team(&self, team_id: TeamId) -> Result<()> {
        self.daemon
            .remove_team(context::current(), team_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Get access to Aranya QUIC Channels.
    pub fn aqc(&self) -> AqcChannels<'_> {
        AqcChannels::new(self)
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
#[derive(Debug)]
pub struct Team<'a> {
    client: &'a Client,
    team_id: TeamId,
}

impl Team<'_> {
    /// Return the team's ID.
    pub fn team_id(&self) -> TeamId {
        self.team_id
    }

    /// Encrypt PSK seed for peer.
    /// `peer_enc_pk` is the public encryption key of the peer device.
    ///
    /// This method will be removed soon since certificates will be used instead of PSKs in the future.
    ///
    /// See [`KeyBundle::encoding`].
    pub async fn encrypt_psk_seed_for_peer(&self, peer_enc_pk: &[u8]) -> Result<Vec<u8>> {
        let peer_enc_pk: EncryptionPublicKey<CS> = postcard::from_bytes(peer_enc_pk)
            .context("bad peer_enc_pk")
            .map_err(error::other)?;
        let wrapped = self
            .client
            .daemon
            .encrypt_psk_seed_for_peer(context::current(), self.team_id, peer_enc_pk)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        let wrapped = postcard::to_allocvec(&wrapped).assume("can serialize")?;
        Ok(wrapped)
    }

    /// Adds a peer for automatic periodic Aranya state syncing.
    pub async fn add_sync_peer(&self, addr: Addr, config: SyncPeerConfig) -> Result<()> {
        self.client
            .daemon
            .add_sync_peer(context::current(), addr, self.team_id, config.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Immediately syncs with the peer.
    ///
    /// If `config` is `None`, default values (including those from the daemon) will
    /// be used.
    pub async fn sync_now(&self, addr: Addr, cfg: Option<SyncPeerConfig>) -> Result<()> {
        self.client
            .daemon
            .sync_now(context::current(), addr, self.team_id, cfg.map(Into::into))
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes a peer from automatic Aranya state syncing.
    pub async fn remove_sync_peer(&self, addr: Addr) -> Result<()> {
        self.client
            .daemon
            .remove_sync_peer(context::current(), addr, self.team_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Close the team and stop all operations on the graph.
    pub async fn close_team(&self) -> Result<()> {
        self.client
            .daemon
            .close_team(context::current(), self.team_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Add a device to the team with the default `Member` role.
    pub async fn add_device_to_team(&self, keys: KeyBundle) -> Result<()> {
        self.client
            .daemon
            .add_device_to_team(context::current(), self.team_id, keys)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Remove a device from the team.
    pub async fn remove_device_from_team(&self, device: DeviceId) -> Result<()> {
        self.client
            .daemon
            .remove_device_from_team(context::current(), self.team_id, device)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Assign a role to a device.
    pub async fn assign_role(&self, device: DeviceId, role: Role) -> Result<()> {
        self.client
            .daemon
            .assign_role(context::current(), self.team_id, device, role)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revoke a role from a device. This sets the device's role back to the default `Member` role.
    pub async fn revoke_role(&self, device: DeviceId, role: Role) -> Result<()> {
        self.client
            .daemon
            .revoke_role(context::current(), self.team_id, device, role)
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
        &self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        self.client
            .daemon
            .assign_aqc_net_identifier(context::current(), self.team_id, device, net_identifier)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Disassociate an AQC network identifier from a device.
    pub async fn remove_aqc_net_identifier(
        &self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        self.client
            .daemon
            .remove_aqc_net_identifier(context::current(), self.team_id, device, net_identifier)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Create a label.
    pub async fn create_label(&self, label_name: Text) -> Result<LabelId> {
        self.client
            .daemon
            .create_label(context::current(), self.team_id, label_name)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Delete a label.
    pub async fn delete_label(&self, label_id: LabelId) -> Result<()> {
        self.client
            .daemon
            .delete_label(context::current(), self.team_id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Assign a label to a device.
    pub async fn assign_label(
        &self,
        device: DeviceId,
        label_id: LabelId,
        op: ChanOp,
    ) -> Result<()> {
        self.client
            .daemon
            .assign_label(context::current(), self.team_id, device, label_id, op)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revoke a label from a device.
    pub async fn revoke_label(&self, device: DeviceId, label_id: LabelId) -> Result<()> {
        self.client
            .daemon
            .revoke_label(context::current(), self.team_id, device, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Get access to fact database queries.
    pub fn queries(&self) -> Queries<'_> {
        Queries {
            client: self.client,
            team_id: self.team_id,
        }
    }
}

/// Queries the Aranya fact database.
///
/// The fact database is updated when actions/effects are processed for a team.
#[derive(Debug)]
pub struct Queries<'a> {
    client: &'a Client,
    team_id: TeamId,
}

impl Queries<'_> {
    /// Returns the list of devices on the current team.
    pub async fn devices_on_team(&self) -> Result<Devices> {
        let data = self
            .client
            .daemon
            .query_devices_on_team(context::current(), self.team_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Devices { data })
    }

    /// Returns the role of the current device.
    pub async fn device_role(&self, device: DeviceId) -> Result<Role> {
        self.client
            .daemon
            .query_device_role(context::current(), self.team_id, device)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns the keybundle of the current device.
    pub async fn device_keybundle(&self, device: DeviceId) -> Result<KeyBundle> {
        self.client
            .daemon
            .query_device_keybundle(context::current(), self.team_id, device)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns a list of labels assiged to the current device.
    pub async fn device_label_assignments(&self, device: DeviceId) -> Result<Labels> {
        let data = self
            .client
            .daemon
            .query_device_label_assignments(context::current(), self.team_id, device)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Labels { data })
    }

    /// Returns the AQC network identifier assigned to the current device.
    pub async fn aqc_net_identifier(&self, device: DeviceId) -> Result<Option<NetIdentifier>> {
        self.client
            .daemon
            .query_aqc_net_identifier(context::current(), self.team_id, device)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns whether a label exists.
    pub async fn label_exists(&self, label_id: LabelId) -> Result<bool> {
        self.client
            .daemon
            .query_label_exists(context::current(), self.team_id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns a list of labels on the team.
    pub async fn labels(&self) -> Result<Labels> {
        let data = self
            .client
            .daemon
            .query_labels(context::current(), self.team_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Labels { data })
    }
}
