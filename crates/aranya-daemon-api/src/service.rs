#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::{fmt, hash::Hash, net::SocketAddr, time::Duration};

use aranya_base58::ToBase58;
use aranya_crypto::{
    afc::{BidiChannelId, UniChannelId},
    custom_id,
    default::DefaultCipherSuite,
    Id,
};
use aranya_fast_channels::{Label, NodeId};
use aranya_util::Addr;
use serde::{Deserialize, Serialize};
use tracing::error;

/// CS = Cipher Suite
pub type CS = DefaultCipherSuite;

/// An error returned by the API.
// TODO: enum?
#[derive(Serialize, Deserialize, Debug)]
pub struct Error(String);

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

/// A device's public key bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBundle {
    pub identity: Vec<u8>,
    pub signing: Vec<u8>,
    pub encoding: Vec<u8>,
}

/// A device's role on the team.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Admin,
    Operator,
    Member,
}

/// A device's network identifier.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetIdentifier(pub String);

impl AsRef<str> for NetIdentifier {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NetIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Uniquely identifies an AFC channel.
///
/// It is a [`BidiChannelId`] or [`UniChannelId`] truncated to
/// 128 bits.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AfcId([u8; 16]);

impl fmt::Display for AfcId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_base58())
    }
}

fn truncate<const BIG: usize, const SMALL: usize>(arr: &[u8; BIG]) -> &[u8; SMALL] {
    const { assert!(BIG >= SMALL) };
    arr[..SMALL].try_into().expect("array must fit")
}

/// Convert from [`BidiChannelId`] to [`AfcId`]
impl From<BidiChannelId> for AfcId {
    fn from(value: BidiChannelId) -> Self {
        Self(*truncate(value.as_array()))
    }
}

/// Convert from [`UniChannelId`] to [`AfcId`]
impl From<UniChannelId> for AfcId {
    fn from(value: UniChannelId) -> Self {
        Self(*truncate(value.as_array()))
    }
}

/// Convert from [`Id`] to [`AfcId`]
impl From<Id> for AfcId {
    fn from(value: Id) -> Self {
        Self(*truncate(value.as_array()))
    }
}

// serialized command which must be passed over AFC.
pub type AfcCtrl = Vec<Box<[u8]>>;

#[tarpc::service]
pub trait DaemonApi {
    /// Gets local address the Aranya sync server is bound to.
    async fn aranya_local_addr() -> Result<SocketAddr>;

    /// Gets the public key bundle for this device
    async fn get_key_bundle() -> Result<KeyBundle>;

    /// Gets the public device id.
    async fn get_device_id() -> Result<DeviceId>;

    /// Adds the peer for automatic periodic syncing.
    async fn add_sync_peer(
        addr: Addr,
        team: TeamId,
        interval: Duration,
        sync_now: bool,
    ) -> Result<()>;

    /// Sync with peer immediately.
    async fn sync_now(addr: Addr, team: TeamId) -> Result<()>;

    /// Removes the peer from automatic syncing.
    async fn remove_sync_peer(addr: Addr, team: TeamId) -> Result<()>;

    /// add a team to the local device store that was created by someone else. Not an aranya action/command.
    async fn add_team(team: TeamId) -> Result<()>;

    /// remove a team from the local device store.
    async fn remove_team(team: TeamId) -> Result<()>;

    /// Create a new graph/team with the current device as the owner.
    async fn create_team() -> Result<TeamId>;
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

    /// Assign a network identifier to a device.
    async fn assign_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;
    /// Remove a network identifier from a device.
    async fn remove_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;

    /// Create a fast channels label.
    async fn create_label(team: TeamId, label: Label) -> Result<()>;
    /// Delete a fast channels label.
    async fn delete_label(team: TeamId, label: Label) -> Result<()>;

    /// Assign a fast channels label to a device.
    async fn assign_label(team: TeamId, device: DeviceId, label: Label) -> Result<()>;
    /// Revoke a fast channels label from a device.
    async fn revoke_label(team: TeamId, device: DeviceId, label: Label) -> Result<()>;
    /// Create a fast channel.
    async fn create_bidi_channel(
        team: TeamId,
        peer: NetIdentifier,
        node_id: NodeId,
        label: Label,
    ) -> Result<(AfcId, AfcCtrl)>;
    /// Delete a fast channel.
    async fn delete_channel(chan: AfcId) -> Result<AfcCtrl>;
    /// Receive a fast channel ctrl message.
    async fn receive_afc_ctrl(
        team: TeamId,
        node_id: NodeId,
        ctrl: AfcCtrl,
    ) -> Result<(AfcId, NetIdentifier, Label)>;
}
