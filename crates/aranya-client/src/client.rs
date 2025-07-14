//! Client-daemon connection.

use std::{
    ffi::CStr,
    fmt, io,
    net::SocketAddr,
    path::Path,
    slice,
    str::{FromStr, Utf8Error},
    vec,
};

use anyhow::Context as _;
use aranya_crypto::{Csprng, EncryptionPublicKey, Rng};
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
use aranya_policy_text::Text;
use aranya_util::Addr;
use buggy::BugExt as _;
use tarpc::context;
use tokio::{fs, net::UnixStream};
use tracing::{debug, error, info, instrument};

use crate::{
    aqc::{AqcChannels, AqcClient},
    config::{SyncPeerConfig, TeamConfig},
    error::{self, aranya_error, Error, InvalidArg, IpcError, Result},
    util::{custom_id, impl_slice_iter_wrapper, impl_vec_into_iter_wrapper},
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
#[non_exhaustive]
pub struct Label {
    pub id: LabelId,
    pub name: Text,
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
#[non_exhaustive]
pub struct Role {
    /// Uniquely identifies the role.
    pub id: RoleId,
    /// The humman-readable name of the role.
    pub name: Text,
    /// The unique ID of the author of the role.
    pub author_id: DeviceId,
    /// Is this a default role?
    pub default: bool,
}

impl Role {
    pub(crate) fn from_api(v: api::Role) -> Self {
        Self {
            id: RoleId::from_api(v.id),
            name: v.name,
            author_id: DeviceId::from_api(v.author_id),
            default: v.default,
        }
    }
}

/// A set of [`Role`]s.
#[derive(Clone, Debug)]
pub struct Roles {
    roles: Box<[Role]>,
}

impl Roles {
    /// Returns an iterator over the roles.
    pub fn iter(&self) -> IterRoles<'_> {
        IterRoles(self.roles.iter())
    }

    #[doc(hidden)]
    pub fn __into_data(self) -> Box<[Role]> {
        self.roles
    }
}

impl IntoIterator for Roles {
    type Item = Role;
    type IntoIter = IntoIterRoles;

    fn into_iter(self) -> Self::IntoIter {
        IntoIterRoles(self.roles.into_vec().into_iter())
    }
}

/// An iterator over [`Role`]s.
#[derive(Clone, Debug)]
pub struct IterRoles<'a>(slice::Iter<'a, Role>);

impl_slice_iter_wrapper!(IterRoles<'a> for Role);

/// An owning iterator over [`Role`]s.
#[derive(Clone, Debug)]
pub struct IntoIterRoles(vec::IntoIter<Role>);

impl_vec_into_iter_wrapper!(IntoIterRoles for Role);

/// List of operations.
#[derive(Clone, Debug)]
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
pub struct NetIdentifier(Text);

impl NetIdentifier {
    pub(crate) fn into_api(self) -> api::NetIdentifier {
        api::NetIdentifier(self.0)
    }
}

impl AsRef<str> for NetIdentifier {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl TryFrom<SocketAddr> for NetIdentifier {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(addr: SocketAddr) -> Result<Self, Self::Error> {
        Self::try_from(addr.to_string())
    }
}

impl TryFrom<&str> for NetIdentifier {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(id: &str) -> Result<Self, Self::Error> {
        Text::from_str(id)
            .map_err(|_| InvalidNetIdentifier(()))
            .map(Self)
    }
}

impl TryFrom<&CStr> for NetIdentifier {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(id: &CStr) -> Result<Self, Self::Error> {
        Text::try_from(id)
            .map_err(|_| InvalidNetIdentifier(()))
            .map(Self)
    }
}

impl TryFrom<String> for NetIdentifier {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(id: String) -> Result<Self, Self::Error> {
        Text::try_from(id)
            .map_err(|_| InvalidNetIdentifier(()))
            .map(Self)
    }
}

impl fmt::Display for NetIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The [`NetIdentifier`] is invalid.
#[derive(Debug, thiserror::Error)]
#[error("invalid net identifier")]
pub struct InvalidNetIdentifier(pub(crate) ());

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
#[derive(Clone, Debug)]
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
            .map(DeviceId::from_api)
    }

    /// Create a new graph/team with the current device as the owner.
    pub async fn create_team(&self, cfg: TeamConfig) -> Result<Team<'_>> {
        let team_id = self
            .daemon
            .create_team(context::current(), cfg.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Team {
            client: self,
            id: team_id,
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
            id: team_id.into_api(),
        }
    }

    /// Add a team to the local device store.
    pub async fn add_team(&self, team: TeamId, cfg: TeamConfig) -> Result<()> {
        self.daemon
            .add_team(context::current(), team.into_api(), cfg.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Remove a team from local device storage.
    pub async fn remove_team(&self, team_id: TeamId) -> Result<()> {
        self.daemon
            .remove_team(context::current(), team_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Get access to Aranya QUIC Channels.
    pub fn aqc(&self) -> AqcChannels<'_> {
        AqcChannels::new(self)
    }

    /// Get access to fact database queries.
    pub fn queries(&self, id: TeamId) -> Queries<'_> {
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
#[derive(Debug)]
pub struct Team<'a> {
    client: &'a Client,
    id: api::TeamId,
}

impl Team<'_> {
    /// Return the team's ID.
    pub fn team_id(&self) -> TeamId {
        TeamId::from_api(self.id)
    }

    /// Returns the [`Device`] corresponding with `id`.
    pub fn device(&self, id: DeviceId) -> Device<'_> {
        Device {
            client: self.client,
            team_id: self.id,
            id: id.into_api(),
        }
    }

    /// Encrypt PSK seed for peer.
    /// `peer_enc_pk` is the public encryption key of the peer device.
    /// See [`KeyBundle::encoding`].
    #[instrument(skip(self))]
    pub async fn encrypt_psk_seed_for_peer(&self, peer_enc_pk: &[u8]) -> Result<Vec<u8>> {
        let peer_enc_pk: EncryptionPublicKey<CS> = postcard::from_bytes(peer_enc_pk)
            .context("bad peer_enc_pk")
            .map_err(error::other)?;
        let wrapped = self
            .client
            .daemon
            .encrypt_psk_seed_for_peer(context::current(), self.id, peer_enc_pk)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        let wrapped = postcard::to_allocvec(&wrapped).assume("can serialize")?;
        Ok(wrapped)
    }

    /// Adds a peer for automatic periodic Aranya state syncing.
    #[instrument(skip(self))]
    pub async fn add_sync_peer(&self, addr: Addr, config: SyncPeerConfig) -> Result<()> {
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
    #[instrument(skip(self))]
    pub async fn sync_now(&self, addr: Addr, cfg: Option<SyncPeerConfig>) -> Result<()> {
        self.client
            .daemon
            .sync_now(context::current(), addr, self.id, cfg.map(Into::into))
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes a peer from automatic Aranya state syncing.
    #[instrument(skip(self))]
    pub async fn remove_sync_peer(&self, addr: Addr) -> Result<()> {
        self.client
            .daemon
            .remove_sync_peer(context::current(), addr, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Close the team and stop all operations on the graph.
    #[instrument(skip(self))]
    pub async fn close_team(&self) -> Result<()> {
        self.client
            .daemon
            .close_team(context::current(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Add a device to the team with optional initial roles.
    // TODO(eric): why does this have a "_to_team" suffix when
    // it's a method on `Team`?
    #[instrument(skip(self, initial_roles))]
    pub async fn add_device_to_team<I>(&self, keys: KeyBundle, initial_roles: I) -> Result<()>
    where
        I: IntoIterator<Item = RoleId>,
    {
        self.client
            .daemon
            .add_device_to_team(
                context::current(),
                self.id,
                keys,
                initial_roles.into_iter().map(|id| id.into_api()).collect(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Remove a device from the team.
    #[instrument(skip(self))]
    pub async fn remove_device_from_team(&self, device: DeviceId) -> Result<()> {
        self.client
            .daemon
            .remove_device_from_team(context::current(), self.id, device.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Sets up the default team roles.
    ///
    /// The `managing_role_id` is the role that is required to
    /// manage all of the default roles.
    ///
    /// It returns the newly created roles.
    #[instrument(skip(self))]
    pub async fn setup_default_roles(&self, managing_role_id: RoleId) -> Result<Roles> {
        let roles = self
            .client
            .daemon
            .setup_default_roles(context::current(), self.id, managing_role_id.into_api())
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
        Ok(Roles { roles })
    }

    /// Adds `owning_role` as an owner of the target role.
    #[instrument(skip(self))]
    pub async fn add_role_owner(&self, role: RoleId, owning_role: RoleId) -> Result<()> {
        self.client
            .daemon
            .add_role_owner(
                context::current(),
                self.id,
                role.into_api(),
                owning_role.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes an owning role as an owner of the target role.
    #[instrument(skip(self))]
    pub async fn remove_role_owner(&self, role: RoleId, owning_role: RoleId) -> Result<()> {
        self.client
            .daemon
            .remove_role_owner(
                context::current(),
                self.id,
                role.into_api(),
                owning_role.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Assigns a role management permission to a managing role.
    #[instrument(skip(self))]
    pub async fn assign_role_management_permission(
        &self,
        role: RoleId,
        managing_role: RoleId,
        perm: Text,
    ) -> Result<()> {
        self.client
            .daemon
            .assign_role_management_perm(
                context::current(),
                self.id,
                role.into_api(),
                managing_role.into_api(),
                perm,
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revokes a role management permission from a managing
    /// role.
    #[instrument(skip(self))]
    pub async fn revoke_role_management_permission(
        &self,
        role: RoleId,
        managing_role: RoleId,
        perm: Text,
    ) -> Result<()> {
        self.client
            .daemon
            .assign_role_management_perm(
                context::current(),
                self.id,
                role.into_api(),
                managing_role.into_api(),
                perm,
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Assigns a role to a device.
    #[instrument(skip(self))]
    pub async fn assign_role(&self, device: DeviceId, role: RoleId) -> Result<()> {
        self.client
            .daemon
            .assign_role(
                context::current(),
                self.id,
                device.into_api(),
                role.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revoke a role from a device.
    #[instrument(skip(self))]
    pub async fn revoke_role(&self, device: DeviceId, role: RoleId) -> Result<()> {
        self.client
            .daemon
            .revoke_role(
                context::current(),
                self.id,
                device.into_api(),
                role.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns an iterator over the roles in the team.
    #[instrument(skip(self))]
    pub async fn roles(&self) -> Result<Roles> {
        let roles = self
            .client
            .daemon
            .query_team_roles(context::current(), self.id)
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
        Ok(Roles { roles })
    }

    /// Associate a network identifier to a device for use with AQC.
    ///
    /// If the address already exists for this device, it is replaced with the new address. Capable
    /// of resolving addresses via DNS, required to be statically mapped to IPV4. For use with
    /// OpenChannel and receiving messages. Can take either DNS name or IPV4.
    #[instrument(skip(self, net_identifier))]
    pub async fn assign_aqc_net_identifier<I>(
        &self,
        device: DeviceId,
        net_identifier: I,
    ) -> Result<()>
    where
        I: TryInto<NetIdentifier>,
    {
        self.client
            .daemon
            .assign_aqc_net_identifier(
                context::current(),
                self.id,
                device.into_api(),
                net_identifier
                    .try_into()
                    .map_err(|_| InvalidNetIdentifier(()))?
                    .into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Disassociate an AQC network identifier from a device.
    #[instrument(skip(self, net_identifier))]
    pub async fn remove_aqc_net_identifier<I>(
        &self,
        device: DeviceId,
        net_identifier: I,
    ) -> Result<()>
    where
        I: TryInto<NetIdentifier>,
    {
        self.client
            .daemon
            .remove_aqc_net_identifier(
                context::current(),
                self.id,
                device.into_api(),
                net_identifier
                    .try_into()
                    .map_err(|_| InvalidNetIdentifier(()))?
                    .into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Create a label.
    #[instrument(skip(self, label_name))]
    pub async fn create_label<T>(&self, label_name: T, managing_role_id: RoleId) -> Result<LabelId>
    where
        T: TryInto<Text>,
    {
        self.client
            .daemon
            .create_label(
                context::current(),
                self.id,
                label_name
                    .try_into()
                    // TODO(eric): Use a different error.
                    .map_err(|_| InvalidNetIdentifier(()))?,
                managing_role_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(LabelId::from_api)
    }

    /// Delete a label.
    #[instrument(skip(self))]
    pub async fn delete_label(&self, label_id: LabelId) -> Result<()> {
        self.client
            .daemon
            .delete_label(context::current(), self.id, label_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Assign a label to a device.
    #[instrument(skip(self))]
    pub async fn assign_label(
        &self,
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
    #[instrument(skip(self))]
    pub async fn revoke_label(&self, device: DeviceId, label_id: LabelId) -> Result<()> {
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

    /// Get access to fact database queries.
    pub fn queries(&self) -> Queries<'_> {
        Queries {
            client: self.client,
            id: self.id,
        }
    }
}

#[derive(Debug)]
pub struct Queries<'a> {
    client: &'a Client,
    id: api::TeamId,
}

impl Queries<'_> {
    /// Returns the list of devices on the current team.
    pub async fn devices_on_team(&self) -> Result<Devices> {
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

    /// Returns the keybundle of the current device.
    pub async fn device_keybundle(&self, device: DeviceId) -> Result<KeyBundle> {
        self.client
            .daemon
            .query_device_keybundle(context::current(), self.id, device.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns a list of labels assiged to the current device.
    pub async fn device_label_assignments(&self, device: DeviceId) -> Result<Labels> {
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

    /// Returns the AQC network identifier assigned to the
    /// current device, if any.
    // TODO(eric): documented whether this returns `None` if the
    // device does not exist or if the device exists but does not
    // have a net ID.
    pub async fn aqc_net_identifier(&self, device: DeviceId) -> Result<Option<NetIdentifier>> {
        let id = self
            .client
            .daemon
            .query_aqc_net_identifier(context::current(), self.id, device.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            .map(|id| NetIdentifier(id.0));
        Ok(id)
    }

    /// Returns whether a label exists.
    pub async fn label_exists(&self, label_id: LabelId) -> Result<bool> {
        self.client
            .daemon
            .query_label_exists(context::current(), self.id, label_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns a list of labels on the team.
    pub async fn labels(&self) -> Result<Labels> {
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

/// Represents an Aranya device
#[derive(Debug)]
pub struct Device<'a> {
    client: &'a Client,
    id: api::DeviceId,
    team_id: api::TeamId,
}

impl Device<'_> {
    /// Returns the device's unique ID.
    pub fn id(&self) -> DeviceId {
        DeviceId::from_api(self.id)
    }

    /// Returns all roles assigned to the device.
    pub async fn roles(&self) -> Result<Roles> {
        let roles = self
            .client
            .daemon
            .query_device_roles(context::current(), self.team_id, self.id)
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
        Ok(Roles { roles })
    }
}
