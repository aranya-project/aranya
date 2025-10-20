#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::{error, fmt, hash::Hash, net::SocketAddr, time::Duration};

pub use aranya_crypto::tls::CipherSuiteId;
use aranya_crypto::{
    default::DefaultEngine,
    id::IdError,
    subtle::{Choice, ConstantTimeEq},
    zeroize::{Zeroize, ZeroizeOnDrop},
    EncryptionPublicKey, Engine,
};
use aranya_id::custom_id;
pub use aranya_policy_text::{text, Text};
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

/// A device's public key bundle.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct KeyBundle {
    pub identity: Vec<u8>,
    pub signing: Vec<u8>,
    pub encryption: Vec<u8>,
}

/// A device's role on the team.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum Role {
    Owner,
    Admin,
    Operator,
    Member,
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
    /// The interval at which syncing occurs
    pub interval: Duration,
    /// Determines if a peer should be synced with immediately after they're added
    pub sync_now: bool,
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

/// A label.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Label {
    pub id: LabelId,
    pub name: Text,
}

// TODO(jdygert): tarpc does not cfg return types properly.
#[cfg(not(feature = "afc"))]
use afc_stub::{AfcChannelId, AfcCtrl, AfcShmInfo};
#[cfg(not(feature = "afc"))]
mod afc_stub {
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub enum Never {}
    pub type AfcCtrl = Never;
    pub type AfcShmInfo = Never;
    pub type AfcChannelId = Never;
}

#[tarpc::service]
pub trait DaemonApi {
    /// Returns the daemon's version.
    async fn version() -> Result<Version>;

    /// Gets local address the Aranya sync server is bound to.
    async fn aranya_local_addr() -> Result<SocketAddr>;

    /// Gets the public key bundle for this device
    async fn get_key_bundle() -> Result<KeyBundle>;

    /// Gets the public device id.
    async fn get_device_id() -> Result<DeviceId>;

    /// Adds the peer for automatic periodic syncing.
    async fn add_sync_peer(addr: Addr, team: TeamId, config: SyncPeerConfig) -> Result<()>;

    /// Sync with peer immediately.
    async fn sync_now(addr: Addr, team: TeamId, cfg: Option<SyncPeerConfig>) -> Result<()>;

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

    async fn encrypt_psk_seed_for_peer(
        team: TeamId,
        peer_enc_pk: EncryptionPublicKey<CS>,
    ) -> Result<WrappedSeed>;

    /// Add device to the team.
    async fn add_device_to_team(team: TeamId, keys: KeyBundle) -> Result<()>;
    /// Remove device from the team.
    async fn remove_device_from_team(team: TeamId, device: DeviceId) -> Result<()>;

    /// Assign a role to a device.
    async fn assign_role(team: TeamId, device: DeviceId, role: Role) -> Result<()>;
    /// Revoke a role from a device.
    async fn revoke_role(team: TeamId, device: DeviceId, role: Role) -> Result<()>;

    // Create a label.
    async fn create_label(team: TeamId, name: Text) -> Result<LabelId>;
    // Delete a label.
    async fn delete_label(team: TeamId, label_id: LabelId) -> Result<()>;
    // Assign a label to a device.
    async fn assign_label(
        team: TeamId,
        device: DeviceId,
        label_id: LabelId,
        op: ChanOp,
    ) -> Result<()>;
    // Revoke a label from a device.
    async fn revoke_label(team: TeamId, device: DeviceId, label_id: LabelId) -> Result<()>;

    /// Gets AFC shared-memory configuration info.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    async fn afc_shm_info() -> Result<AfcShmInfo>;
    /// Create a unidirectional AFC send-only channel.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    async fn create_afc_uni_send_channel(
        team: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> Result<(AfcCtrl, AfcChannelId)>;
    /// Delete a AFC channel.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    async fn delete_afc_channel(chan: AfcChannelId) -> Result<()>;
    /// Receive AFC ctrl message.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    async fn receive_afc_ctrl(team: TeamId, ctrl: AfcCtrl) -> Result<(LabelId, AfcChannelId)>;

    /// Query devices on team.
    async fn query_devices_on_team(team: TeamId) -> Result<Vec<DeviceId>>;
    /// Query device role.
    async fn query_device_role(team: TeamId, device: DeviceId) -> Result<Role>;
    /// Query device keybundle.
    async fn query_device_keybundle(team: TeamId, device: DeviceId) -> Result<KeyBundle>;
    /// Query device label assignments.
    async fn query_device_label_assignments(team: TeamId, device: DeviceId) -> Result<Vec<Label>>;
    // Query labels on team.
    async fn query_labels(team: TeamId) -> Result<Vec<Label>>;
    /// Query whether a label exists.
    async fn query_label_exists(team: TeamId, label: LabelId) -> Result<bool>;
}
