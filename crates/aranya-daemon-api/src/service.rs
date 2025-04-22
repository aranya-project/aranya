#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::{borrow::Borrow, fmt, hash::Hash, net::SocketAddr, ops::Deref, time::Duration};

use aranya_crypto::{
    custom_id,
    default::{DefaultCipherSuite, DefaultEngine},
    subtle::{Choice, ConstantTimeEq},
    zeroize::{Zeroize, ZeroizeOnDrop},
    Id,
};
use aranya_util::Addr;
use buggy::Bug;
use serde::{Deserialize, Serialize};
use tracing::error;

/// CE = Crypto Engine
pub type CE = DefaultEngine;
/// CS = Cipher Suite
pub type CS = DefaultCipherSuite;

/// An error returned by the API.
// TODO: enum?
#[derive(Serialize, Deserialize, Debug)]
pub struct Error(String);

impl From<Bug> for Error {
    fn from(err: Bug) -> Self {
        error!(?err);
        Self(format!("{err:?}"))
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        error!(?err);
        Self(format!("{err:?}"))
    }
}

impl From<aranya_crypto::id::IdError> for Error {
    fn from(err: aranya_crypto::id::IdError) -> Self {
        error!(%err);
        Self(err.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for Error {}

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
    /// An AQC label ID.
    pub struct LabelId;
}

custom_id! {
    /// An AQC bidi channel ID.
    pub struct AqcBidiChannelId;
}

custom_id! {
    /// An AQC uni channel ID.
    pub struct AqcUniChannelId;
}

/// A device's public key bundle.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct KeyBundle {
    pub identity: Vec<u8>,
    pub signing: Vec<u8>,
    pub encoding: Vec<u8>,
}

/// A device's role on the team.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum Role {
    Owner,
    Admin,
    Operator,
    Member,
}

/// A configuration for creating or adding a team to a daemon.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamConfig {
    // TODO(nikki): any fields added to this should be public
}

/// A device's network identifier.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetIdentifier(pub String);

impl Borrow<str> for NetIdentifier {
    #[inline]
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl<T> AsRef<T> for NetIdentifier
where
    T: ?Sized,
    <Self as Deref>::Target: AsRef<T>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

impl Deref for NetIdentifier {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for NetIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A serialized command for AQC.
pub type AqcCtrl = Vec<Box<[u8]>>;

/// A secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// An AQC PSK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AqcPsk {
    /// Bidirectional.
    Bidi(AqcBidiPsk),
    /// Unidirectional.
    Uni(AqcUniPsk),
}

impl AqcPsk {
    /// Returns the PSK identity.
    #[inline]
    pub fn identity(&self) -> Id {
        match self {
            Self::Bidi(psk) => psk.identity,
            Self::Uni(psk) => psk.identity,
        }
    }

    /// Returns the PSK secret.
    #[inline]
    pub fn secret(&self) -> &[u8] {
        match self {
            Self::Bidi(psk) => psk.secret.raw_secret_bytes(),
            Self::Uni(psk) => match &psk.secret {
                Directed::Send(secret) | Directed::Recv(secret) => secret.raw_secret_bytes(),
            },
        }
    }
}

/// An AQC bidirectional channel PSK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AqcBidiPsk {
    /// The PSK identity.
    ///
    /// This is the same thing as the channel ID.
    pub identity: Id,
    /// The PSK's secret.
    pub secret: Secret,
}

impl ConstantTimeEq for AqcBidiPsk {
    fn ct_eq(&self, other: &Self) -> Choice {
        let id = self.identity.ct_eq(&other.identity);
        let secret = self.secret.ct_eq(&other.secret);
        id & secret
    }
}

impl ZeroizeOnDrop for AqcBidiPsk {}

/// An AQC unidirectional PSK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AqcUniPsk {
    /// The PSK identity.
    ///
    /// This is the same thing as the channel ID.
    pub identity: Id,
    /// The PSK's secret.
    pub secret: Directed<Secret>,
}

impl ConstantTimeEq for AqcUniPsk {
    fn ct_eq(&self, other: &Self) -> Choice {
        let id = self.identity.ct_eq(&other.identity);
        let secret = self.secret.ct_eq(&other.secret);
        id & secret
    }
}

impl ZeroizeOnDrop for AqcUniPsk {}

/// Either send only or receive only.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Directed<T> {
    /// Send only.
    Send(T),
    /// Receive only.
    Recv(T),
}

impl<T: ConstantTimeEq> ConstantTimeEq for Directed<T> {
    fn ct_eq(&self, other: &Self) -> Choice {
        // It's fine that matching discriminants isn't constant
        // time since the direction isn't secret data.
        match (self, other) {
            (Self::Send(lhs), Self::Send(rhs)) => lhs.ct_eq(rhs),
            (Self::Recv(lhs), Self::Recv(rhs)) => lhs.ct_eq(rhs),
            _ => Choice::from(0u8),
        }
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
    /// The device can send and receive data in channels with this
    /// label.
    SendRecv,
}

/// A label.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Label {
    pub id: LabelId,
    pub name: String,
}

#[tarpc::service]
pub trait DaemonApi {
    /// Returns the daemon's version.
    async fn version() -> Result<String>;

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
    async fn add_team(team: TeamId, cfg: TeamConfig) -> Result<()>;

    /// remove a team from the local device store.
    async fn remove_team(team: TeamId) -> Result<()>;

    /// Create a new graph/team with the current device as the owner.
    async fn create_team(cfg: TeamConfig) -> Result<TeamId>;
    /// Close the team.
    async fn close_team(team: TeamId) -> Result<()>;

    /// Add device to the team.
    async fn add_device_to_team(team: TeamId, keys: KeyBundle) -> Result<()>;
    /// Remove device from the team.
    async fn remove_device_from_team(team: TeamId, device: DeviceId) -> Result<()>;

    /// Assign a role to a device.
    async fn assign_role(team: TeamId, device: DeviceId, role: Role) -> Result<()>;
    /// Revoke a role from a device.
    async fn revoke_role(team: TeamId, device: DeviceId, role: Role) -> Result<()>;

    /// Assign a QUIC channels network identifier to a device.
    async fn assign_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;
    /// Remove a QUIC channels network identifier from a device.
    async fn remove_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;

    // Create a label.
    async fn create_label(team: TeamId, name: String) -> Result<LabelId>;
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

    /// Create a bidirectional QUIC channel.
    async fn create_aqc_bidi_channel(
        team: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> Result<(AqcCtrl, AqcBidiPsk)>;
    /// Create a unidirectional QUIC channel.
    async fn create_aqc_uni_channel(
        team: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> Result<(AqcCtrl, AqcUniPsk)>;
    /// Delete a QUIC bidi channel.
    async fn delete_aqc_bidi_channel(chan: AqcBidiChannelId) -> Result<AqcCtrl>;
    /// Delete a QUIC uni channel.
    async fn delete_aqc_uni_channel(chan: AqcUniChannelId) -> Result<AqcCtrl>;
    /// Receive AQC ctrl message.
    async fn receive_aqc_ctrl(team: TeamId, ctrl: AqcCtrl) -> Result<(NetIdentifier, AqcPsk)>;

    /// Query devices on team.
    async fn query_devices_on_team(team: TeamId) -> Result<Vec<DeviceId>>;
    /// Query device role.
    async fn query_device_role(team: TeamId, device: DeviceId) -> Result<Role>;
    /// Query device keybundle.
    async fn query_device_keybundle(team: TeamId, device: DeviceId) -> Result<KeyBundle>;
    /// Query device label assignments.
    async fn query_device_label_assignments(team: TeamId, device: DeviceId) -> Result<Vec<Label>>;
    /// Query AQC network ID.
    async fn query_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
    ) -> Result<Option<NetIdentifier>>;
    // Query labels on team.
    async fn query_labels(team: TeamId) -> Result<Vec<Label>>;
    /// Query whether a label exists.
    async fn query_label_exists(team: TeamId, label: LabelId) -> Result<bool>;
}
