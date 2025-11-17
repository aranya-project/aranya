#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::{error, fmt, hash::Hash, time::Duration};

pub use aranya_crypto::tls::CipherSuiteId;
use aranya_crypto::{
    dangerous::spideroak_crypto::hex::Hex,
    default::DefaultEngine,
    id::IdError,
    subtle::{Choice, ConstantTimeEq},
    zeroize::{Zeroize, ZeroizeOnDrop},
    EncryptionPublicKey, Engine,
};
use aranya_id::custom_id;
pub use aranya_policy_text::{text, InvalidText, Text};
use aranya_util::{error::ReportExt, Addr};
use buggy::Bug;
pub use semver::Version;
use serde::{Deserialize, Serialize};

pub mod afc;
pub mod quic_sync;

#[cfg(feature = "afc")]
pub use self::afc::*;
pub use self::quic_sync::*;

/// CE = Crypto Engine
pub type CE = DefaultEngine;
/// CS = Cipher Suite
pub type CS = <DefaultEngine as Engine>::CS;

/// An error returned by the API.
// TODO: enum?
#[derive(Serialize, Deserialize, Debug)]
pub struct Error(String);

impl Error {
    pub fn from_msg(err: &str) -> Self {
        Self(err.into())
    }

    pub fn from_err<E: error::Error>(err: E) -> Self {
        Self(ReportExt::report(&err).to_string())
    }
}

impl From<Bug> for Error {
    fn from(err: Bug) -> Self {
        Self::from_err(err)
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Self(format!("{err:?}"))
    }
}

impl From<InvalidText> for Error {
    fn from(err: InvalidText) -> Self {
        Self(format!("{err:?}"))
    }
}

impl From<semver::Error> for Error {
    fn from(err: semver::Error) -> Self {
        Self::from_err(err)
    }
}

impl From<IdError> for Error {
    fn from(err: IdError) -> Self {
        Self::from_err(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl error::Error for Error {}

pub type Result<T, E = Error> = core::result::Result<T, E>;

custom_id! {
    /// The Device ID.
    pub struct DeviceId;
}

custom_id! {
    /// The Team ID (a.k.a Graph ID).
    pub struct TeamId;
}

custom_id! {
    /// A label ID.
    pub struct LabelId;
}

custom_id! {
    /// A role ID.
    pub struct RoleId;
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Role {
    /// Uniquely identifies the role.
    pub id: RoleId,
    /// The role's friendly name.
    pub name: Text,
    /// The author of the role.
    pub author_id: DeviceId,
    /// Is this a default role?
    pub default: bool,
}

/// A device's public key bundle.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct KeyBundle {
    pub identity: Vec<u8>,
    pub signing: Vec<u8>,
    pub encryption: Vec<u8>,
}

impl fmt::Debug for KeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBundle")
            .field("identity", &Hex::new(&*self.identity))
            .field("signing", &Hex::new(&*self.signing))
            .field("encryption", &Hex::new(&*self.encryption))
            .finish()
    }
}

// Note: any fields added to this type should be public
/// A configuration for adding a team in the daemon.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddTeamConfig {
    pub team_id: TeamId,
    pub quic_sync: Option<AddTeamQuicSyncConfig>,
}

// Note: any fields added to this type should be public
/// A configuration for creating a team in the daemon.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTeamConfig {
    pub quic_sync: Option<CreateTeamQuicSyncConfig>,
}

/// A label.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Label {
    pub id: LabelId,
    pub name: Text,
    pub author_id: DeviceId,
}

/// A PSK IKM.
#[derive(Clone, Serialize, Deserialize)]
pub struct Ikm([u8; SEED_IKM_SIZE]);

impl Ikm {
    /// Provides access to the raw IKM bytes.
    #[inline]
    pub fn raw_ikm_bytes(&self) -> &[u8; SEED_IKM_SIZE] {
        &self.0
    }
}

impl From<[u8; SEED_IKM_SIZE]> for Ikm {
    fn from(value: [u8; SEED_IKM_SIZE]) -> Self {
        Self(value)
    }
}

impl ConstantTimeEq for Ikm {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ZeroizeOnDrop for Ikm {}
impl Drop for Ikm {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl fmt::Debug for Ikm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikm").finish_non_exhaustive()
    }
}

/// A secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct Secret(Box<[u8]>);

impl Secret {
    /// Provides access to the raw secret bytes.
    #[inline]
    pub fn raw_secret_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<T> From<T> for Secret
where
    T: Into<Box<[u8]>>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl ConstantTimeEq for Secret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ZeroizeOnDrop for Secret {}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret").finish_non_exhaustive()
    }
}

/// Configuration values for syncing with a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncPeerConfig {
    /// The interval at which syncing occurs. If None, the peer will not be periodically synced.
    pub interval: Option<Duration>,
    /// Determines if a peer should be synced with immediately after they're added
    pub sync_now: bool,
    /// Determines if the peer should be synced with when a hello message is received
    /// indicating they have a head that we don't have
    #[cfg(feature = "preview")]
    pub sync_on_hello: bool,
}

/// Valid channel operations for a label assignment.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum ChanOp {
    /// The device can only receive data in channels with this
    /// label.
    RecvOnly,
    /// The device can only send data in channels with this
    /// label.
    SendOnly,
    /// The device can send or receive data in channels with this
    /// label.
    SendRecv,
}

// TODO(jdygert): tarpc does not cfg return types properly.
#[cfg(not(feature = "afc"))]
use afc_stub::{AfcReceiveChannelInfo, AfcSendChannelInfo, AfcShmInfo};
#[cfg(not(feature = "afc"))]
mod afc_stub {
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub enum Never {}
    pub type AfcShmInfo = Never;
    pub type AfcSendChannelInfo = Never;
    pub type AfcReceiveChannelInfo = Never;
}

#[tarpc::service]
pub trait DaemonApi {
    //
    // Misc
    //

    /// Returns the daemon's version.
    async fn version() -> Result<Version>;
    /// Gets local address the Aranya sync server is bound to.
    async fn aranya_local_addr() -> Result<Addr>;

    /// Gets the public key bundle for this device
    async fn get_key_bundle() -> Result<KeyBundle>;
    /// Gets the public device id.
    async fn get_device_id() -> Result<DeviceId>;

    //
    // Syncing
    //

    /// Adds the peer for automatic periodic syncing.
    async fn add_sync_peer(addr: Addr, team: TeamId, config: SyncPeerConfig) -> Result<()>;
    /// Sync with peer immediately.
    async fn sync_now(addr: Addr, team: TeamId, cfg: Option<SyncPeerConfig>) -> Result<()>;

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    async fn sync_hello_subscribe(
        peer: Addr,
        team: TeamId,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Result<()>;

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    async fn sync_hello_unsubscribe(peer: Addr, team: TeamId) -> Result<()>;

    /// Removes the peer from automatic syncing.
    async fn remove_sync_peer(addr: Addr, team: TeamId) -> Result<()>;
    /// add a team to the local device store that was created by someone else. Not an aranya action/command.
    async fn add_team(cfg: AddTeamConfig) -> Result<()>;

    /// Remove a team from local device storage.
    async fn remove_team(team: TeamId) -> Result<()>;

    /// Create a new graph/team with the current device as the owner.
    async fn create_team(cfg: CreateTeamConfig) -> Result<TeamId>;
    /// Close the team.
    async fn close_team(team: TeamId) -> Result<()>;

    /// Encrypts the team's syncing PSK(s) for the peer.
    async fn encrypt_psk_seed_for_peer(
        team: TeamId,
        peer_enc_pk: EncryptionPublicKey<CS>,
    ) -> Result<WrappedSeed>;

    //
    // Device onboarding
    //

    /// Adds a device to the team with optional initial roles.
    async fn add_device_to_team(
        team: TeamId,
        keys: KeyBundle,
        initial_role: Option<RoleId>,
    ) -> Result<()>;
    /// Remove device from the team.
    async fn remove_device_from_team(team: TeamId, device: DeviceId) -> Result<()>;
    /// Returns all the devices on the team.
    async fn devices_on_team(team: TeamId) -> Result<Box<[DeviceId]>>;
    /// Returns the device's key bundle.
    async fn device_keybundle(team: TeamId, device: DeviceId) -> Result<KeyBundle>;

    //
    // Role creation
    //

    /// Configures the team with default roles from policy.
    ///
    /// It returns the default roles that were created.
    async fn setup_default_roles(team: TeamId, owning_role: RoleId) -> Result<Box<[Role]>>;
    /// Creates a new role.
    #[cfg(feature = "preview")]
    async fn create_role(team: TeamId, role_name: Text, owning_role: RoleId) -> Result<Role>;
    /// Deletes a role.
    #[cfg(feature = "preview")]
    async fn delete_role(team: TeamId, role_id: RoleId) -> Result<()>;
    /// Returns the current team roles.
    async fn team_roles(team: TeamId) -> Result<Box<[Role]>>;

    //
    // Role management
    //

    /// Adds a permission to a role.
    #[cfg(feature = "preview")]
    async fn add_perm_to_role(team: TeamId, role: RoleId, perm: Text) -> Result<()>;
    /// Removes a permission from a role.
    #[cfg(feature = "preview")]
    async fn remove_perm_from_role(team: TeamId, role: RoleId, perm: Text) -> Result<()>;
    /// Adds an owning role to the target role.
    #[cfg(feature = "preview")]
    async fn add_role_owner(team: TeamId, role: RoleId, owning_role: RoleId) -> Result<()>;
    /// Removes device's role as an owner of the target `role`.
    #[cfg(feature = "preview")]
    async fn remove_role_owner(team: TeamId, role: RoleId) -> Result<()>;
    /// Returns the roles that own the target role.
    async fn role_owners(team: TeamId, role: RoleId) -> Result<Box<[Role]>>;
    /// Assigns a role management permission to a role.
    #[cfg(feature = "preview")]
    async fn assign_role_management_perm(
        team: TeamId,
        role: RoleId,
        managing_role: RoleId,
        perm: Text,
    ) -> Result<()>;
    /// Revokes a role management permission from a role.
    #[cfg(feature = "preview")]
    async fn revoke_role_management_perm(
        team: TeamId,
        role: RoleId,
        managing_role: RoleId,
        perm: Text,
    ) -> Result<()>;

    //
    // Role assignment
    //

    /// Assign a role to a device.
    async fn assign_role(team: TeamId, device: DeviceId, role: RoleId) -> Result<()>;
    /// Revoke a role from a device.
    async fn revoke_role(team: TeamId, device: DeviceId, role: RoleId) -> Result<()>;
    /// Changes the assigned role of a device.
    async fn change_role(
        team: TeamId,
        device: DeviceId,
        old_role: RoleId,
        new_role: RoleId,
    ) -> Result<()>;
    /// Returns the role assigned to the device.
    async fn device_role(team: TeamId, device: DeviceId) -> Result<Option<Role>>;

    //
    // Label creation
    //

    /// Create a label.
    async fn create_label(team: TeamId, name: Text, managing_role_id: RoleId) -> Result<LabelId>;
    /// Delete a label.
    async fn delete_label(team: TeamId, label_id: LabelId) -> Result<()>;
    /// Returns a specific label.
    async fn label(team: TeamId, label: LabelId) -> Result<Option<Label>>;
    /// Returns all labels on the team.
    async fn labels(team: TeamId) -> Result<Vec<Label>>;

    //
    // Label management
    //

    async fn add_label_managing_role(
        team: TeamId,
        label_id: LabelId,
        managing_role_id: RoleId,
    ) -> Result<()>;

    //
    // Label assignments
    //

    /// Assigns a label to a device.
    async fn assign_label_to_device(
        team: TeamId,
        device: DeviceId,
        label: LabelId,
        op: ChanOp,
    ) -> Result<()>;
    /// Revokes a label from a device.
    async fn revoke_label_from_device(team: TeamId, device: DeviceId, label: LabelId)
        -> Result<()>;
    /// Returns all labels assigned to the device.
    async fn labels_assigned_to_device(team: TeamId, device: DeviceId) -> Result<Box<[Label]>>;

    /// Gets AFC shared-memory configuration info.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    async fn afc_shm_info() -> Result<AfcShmInfo>;
    /// Create a send-only AFC channel.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    async fn create_afc_channel(
        team: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> Result<AfcSendChannelInfo>;
    /// Delete a AFC channel.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    async fn delete_afc_channel(chan: AfcLocalChannelId) -> Result<()>;
    /// Accept a receive-only AFC channel by processing a peer's ctrl message.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    async fn accept_afc_channel(team: TeamId, ctrl: AfcCtrl) -> Result<AfcReceiveChannelInfo>;
}
