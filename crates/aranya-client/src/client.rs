//! Client-daemon connection.

use std::{borrow::Cow, ffi::CStr, fmt, io, net::SocketAddr, path::Path, str::Utf8Error};

use anyhow::Context as _;
use aranya_crypto::Rng;
use aranya_daemon_api::{
    self as api,
    crypto::{
        txp::{self, LengthDelimitedCodec},
        PublicApiKey,
    },
    DaemonApiClient, Version, CS,
};
// TODO(eric): Wrap these.
pub use aranya_daemon_api::{KeyBundle, Op};
use aranya_util::Addr;
use tarpc::context;
use tokio::{fs, net::UnixStream};
use tracing::{debug, error, info, instrument};

use crate::{
    aqc::{AqcChannels, AqcClient},
    config::{SyncPeerConfig, TeamConfig},
    error::{self, aranya_error, Error, InvalidArg, IpcError, Result},
    util::custom_id,
};

custom_id! {
    /// The Team ID (a.k.a Graph ID).
    pub struct TeamId;
}

custom_id! {
    /// Uniquely identifies a device.
    pub struct DeviceId;
}

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

custom_id! {
    /// An AQC label ID.
    pub struct LabelId;
}

/// A label.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Label {
    pub id: LabelId,
    pub name: String,
    pub author_id: DeviceId,
}

impl Label {
    pub(crate) fn from_api(v: api::Label) -> Self {
        Self {
            id: LabelId::from_api(v.id),
            name: v.name,
            author_id: DeviceId::from_api(v.author_id),
        }
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

    #[doc(hidden)]
    pub fn __into_data(self) -> Vec<Label> {
        self.data
    }
}

custom_id! {
    /// Uniquely identifies a role.
    pub struct RoleId;
}

/// A role.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub author_id: DeviceId,
}

impl Role {
    pub(crate) fn from_api(v: api::Role) -> Self {
        Self {
            id: RoleId::from_api(v.id),
            name: v.name,
            author_id: DeviceId::from_api(v.author_id),
        }
    }
}

/// List of roles.
pub struct Roles {
    data: Box<[Role]>,
}

impl Roles {
    pub fn iter(&self) -> impl Iterator<Item = &Role> {
        self.data.iter()
    }

    #[doc(hidden)]
    pub fn __into_data(self) -> Box<[Role]> {
        self.data
    }
}

/// List of operations.
pub struct Ops {
    data: Vec<Op>,
}

impl Ops {
    pub fn iter(&self) -> impl Iterator<Item = &Op> {
        self.data.iter()
    }

    #[doc(hidden)]
    pub fn __into_data(self) -> Vec<Op> {
        self.data
    }
}

/// A device's network identifier.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NetIdentifier<'a>(Cow<'a, str>);

impl NetIdentifier<'_> {
    pub(crate) fn into_api(self) -> api::NetIdentifier {
        api::NetIdentifier(self.0.into_owned())
    }
}

impl AsRef<str> for NetIdentifier<'_> {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<'a> TryFrom<&'a str> for NetIdentifier<'a> {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(id: &'a str) -> Result<Self, Self::Error> {
        if id.as_bytes().contains(&0) {
            Err(InvalidNetIdentifier(()))
        } else {
            Ok(Self(Cow::Borrowed(id)))
        }
    }
}

impl<'a> TryFrom<&'a CStr> for NetIdentifier<'a> {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(id: &'a CStr) -> Result<Self, Self::Error> {
        Self::try_from(id.to_str()?)
    }
}

impl TryFrom<String> for NetIdentifier<'_> {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(id: String) -> Result<Self, Self::Error> {
        if id.as_bytes().contains(&0) {
            Err(InvalidNetIdentifier(()))
        } else {
            Ok(Self(Cow::Owned(id)))
        }
    }
}

impl fmt::Display for NetIdentifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The [`NetIdentifier`] is invalid.
#[derive(Debug, thiserror::Error)]
#[error("invalid net identifier")]
pub struct InvalidNetIdentifier(());

impl From<InvalidNetIdentifier> for Error {
    #[inline]
    fn from(err: InvalidNetIdentifier) -> Self {
        error::other(err).into()
    }
}

impl From<Utf8Error> for InvalidNetIdentifier {
    #[inline]
    fn from(_err: Utf8Error) -> Self {
        Self(())
    }
}

/// Valid channel operations for a label assignment.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum ChanOp {
    /// The device can only receive data in channels with this
    /// label.
    RecvOnly,
    /// The device can only send data in channels with this
    /// label.
    SendOnly,
    /// The device can send and receive data in channels with this
    /// label.
    SendRecv,
}

impl ChanOp {
    const fn to_api(self) -> api::ChanOp {
        match self {
            Self::RecvOnly => api::ChanOp::RecvOnly,
            Self::SendOnly => api::ChanOp::SendOnly,
            Self::SendRecv => api::ChanOp::SendRecv,
        }
    }
}

/// Builds a [`Client`].
pub struct ClientBuilder<'a> {
    /// The UDS that the daemon is listening on.
    #[cfg(unix)]
    uds_path: Option<&'a Path>,
    // AQC address.
    aqc_addr: Option<&'a Addr>,
}

impl ClientBuilder<'_> {
    pub fn new() -> Self {
        Self {
            uds_path: None,
            aqc_addr: None,
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

        let Some(aqc_addr) = &self.aqc_addr else {
            return Err(IpcError::new(InvalidArg::new(
                "with_daemon_aqc_addr",
                "must specify the AQC server address",
            ))
            .into());
        };
        Client::connect(sock, aqc_addr)
            .await
            .inspect_err(|err| error!(?err, "unable to connect to daemon"))
    }
}

impl Default for ClientBuilder<'_> {
    fn default() -> Self {
        Self::new()
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

    /// Specifies the AQC server address.
    pub fn with_daemon_aqc_addr(mut self, addr: &'a Addr) -> Self {
        self.aqc_addr = Some(addr);
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
    #[instrument(skip_all, fields(?uds_path))]
    async fn connect(uds_path: &Path, aqc_addr: &Addr) -> Result<Self> {
        info!("connecting to daemon");

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
        Ok(self.aqc.client_addr()?)
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
            .map(DeviceId::from_api)
    }

    /// Create a new graph/team with the current device as the owner.
    pub async fn create_team(&mut self, cfg: TeamConfig) -> Result<TeamId> {
        self.daemon
            .create_team(context::current(), cfg.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(TeamId::from_api)
    }

    /// Add a team to the local device store.
    pub async fn add_team(&mut self, team: TeamId, cfg: TeamConfig) -> Result<()> {
        self.daemon
            .add_team(context::current(), team.into_api(), cfg.into())
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
        Team {
            client: self,
            id: id.into_api(),
        }
    }

    /// Get access to Aranya QUIC Channels.
    pub fn aqc(&mut self) -> AqcChannels<'_> {
        AqcChannels::new(self)
    }

    /// Get access to fact database queries.
    pub fn queries(&mut self, id: TeamId) -> Queries<'_> {
        Queries {
            client: self,
            id: id.into_api(),
        }
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
    id: api::TeamId,
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
    pub async fn add_device_to_team(
        &mut self,
        keys: KeyBundle,
        role_id: Option<RoleId>,
    ) -> Result<()> {
        self.client
            .daemon
            .add_device_to_team(
                context::current(),
                self.id,
                keys,
                role_id.map(|id| id.into_api()),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Remove a device from the team.
    pub async fn remove_device_from_team(&mut self, device: DeviceId) -> Result<()> {
        self.client
            .daemon
            .remove_device_from_team(context::current(), self.id, device.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Sets up the default team roles.
    pub async fn setup_default_roles(&mut self) -> Result<()> {
        self.client
            .daemon
            .setup_default_roles(context::current(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Assign a role to a device.
    pub async fn assign_role(&mut self, device: DeviceId, role_id: RoleId) -> Result<()> {
        self.client
            .daemon
            .assign_role(
                context::current(),
                self.id,
                device.into_api(),
                role_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revoke a role from a device. This sets the device's role back to the default `Member` role.
    pub async fn revoke_role(&mut self, device: DeviceId, role_id: RoleId) -> Result<()> {
        self.client
            .daemon
            .revoke_role(
                context::current(),
                self.id,
                device.into_api(),
                role_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Associate a network identifier to a device for use with AQC.
    ///
    /// If the address already exists for this device, it is replaced with the new address. Capable
    /// of resolving addresses via DNS, required to be statically mapped to IPV4. For use with
    /// OpenChannel and receiving messages. Can take either DNS name or IPV4.
    pub async fn assign_aqc_net_identifier<'a, I>(
        &mut self,
        device: DeviceId,
        net_identifier: I,
    ) -> Result<()>
    where
        I: TryInto<NetIdentifier<'a>, Error = InvalidNetIdentifier>,
    {
        self.client
            .daemon
            .assign_aqc_net_identifier(
                context::current(),
                self.id,
                device.into_api(),
                net_identifier.try_into()?.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Disassociate an AQC network identifier from a device.
    pub async fn remove_aqc_net_identifier<'a, I>(
        &mut self,
        device: DeviceId,
        net_identifier: I,
    ) -> Result<()>
    where
        I: TryInto<NetIdentifier<'a>, Error = InvalidNetIdentifier>,
    {
        self.client
            .daemon
            .remove_aqc_net_identifier(
                context::current(),
                self.id,
                device.into_api(),
                net_identifier.try_into()?.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Create a label.
    pub async fn create_label(
        &mut self,
        label_name: String,
        managing_role_id: RoleId,
    ) -> Result<LabelId> {
        self.client
            .daemon
            .create_label(
                context::current(),
                self.id,
                label_name,
                managing_role_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(LabelId::from_api)
    }

    /// Delete a label.
    pub async fn delete_label(&mut self, label_id: LabelId) -> Result<()> {
        self.client
            .daemon
            .delete_label(context::current(), self.id, label_id.into_api())
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
            .assign_label(
                context::current(),
                self.id,
                device.into_api(),
                label_id.into_api(),
                op.to_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revoke a label from a device.
    pub async fn revoke_label(&mut self, device: DeviceId, label_id: LabelId) -> Result<()> {
        self.client
            .daemon
            .revoke_label(
                context::current(),
                self.id,
                device.into_api(),
                label_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}

pub struct Queries<'a> {
    client: &'a mut Client,
    id: api::TeamId,
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
            .map_err(aranya_error)?
            .into_iter()
            .map(DeviceId::from_api)
            .collect();
        Ok(Devices { data })
    }

    /// Returns the role of the current device.
    pub async fn device_role(&mut self, device: DeviceId) -> Result<Roles> {
        let data = self
            .client
            .daemon
            .query_device_roles(context::current(), self.id, device.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            // This _should_ just be `into_iter`, but the
            // compiler chooses the `&Box` impl. It's the same
            // end result, though.
            .into_vec()
            .into_iter()
            .map(Role::from_api)
            .collect();
        Ok(Roles { data })
    }

    /// Returns the keybundle of the current device.
    pub async fn device_keybundle(&mut self, device: DeviceId) -> Result<KeyBundle> {
        self.client
            .daemon
            .query_device_keybundle(context::current(), self.id, device.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns a list of labels assiged to the current device.
    pub async fn device_label_assignments(&mut self, device: DeviceId) -> Result<Labels> {
        let data = self
            .client
            .daemon
            .query_device_label_assignments(context::current(), self.id, device.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            .into_iter()
            .map(Label::from_api)
            .collect();
        Ok(Labels { data })
    }

    /// Returns the AQC network identifier assigned to the current device.
    pub async fn aqc_net_identifier<'a>(
        &mut self,
        device: DeviceId,
    ) -> Result<Option<NetIdentifier<'a>>> {
        let id = self
            .client
            .daemon
            .query_aqc_net_identifier(context::current(), self.id, device.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            .map(|id| NetIdentifier::try_from(id.0))
            .transpose()?;
        Ok(id)
    }

    /// Returns whether a label exists.
    pub async fn label_exists(&mut self, label_id: LabelId) -> Result<bool> {
        self.client
            .daemon
            .query_label_exists(context::current(), self.id, label_id.into_api())
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
            .map_err(aranya_error)?
            .into_iter()
            .map(Label::from_api)
            .collect();
        Ok(Labels { data })
    }
}
