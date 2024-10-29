#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::time::Duration;
use std::{fmt, net::SocketAddr};

use aranya_crypto::{
    afc::{BidiChannelId, UniChannelId},
    custom_id,
    default::DefaultCipherSuite,
    Id,
};
use aranya_fast_channels::{Label, NodeId};
use aranya_util::Addr;
use serde::{Deserialize, Serialize};

/// CS = Cipher Suite
pub type CS = DefaultCipherSuite;

// TODO: support custom error types.
#[derive(Serialize, Deserialize, Debug, thiserror::Error)]
pub enum Error {
    Unknown,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

custom_id! {
    pub struct DeviceId;
}

custom_id! {
    pub struct TeamId;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBundle {
    pub identity: Vec<u8>,
    pub signing: Vec<u8>,
    pub encoding: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Admin,
    Operator,
    Member,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetIdentifier(pub String);

/// Number of bytes in the [`AfcId`]
const AFC_ID_LEN: usize = 16;

/// [`AfcId`] is a [`BidiChannelId`] or [`UniChannelId`]
/// truncated from 512 bits down to 128 bits.
/// It uniquely identifies an Aranya fast channel.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct AfcId {
    id: [u8; AFC_ID_LEN],
}

fn truncate<const BIG: usize, const SMALL: usize>(arr: &[u8; BIG]) -> &[u8; SMALL] {
    const { assert!(BIG >= SMALL) };
    arr[..SMALL].try_into().expect("array must fit")
}

/// Convert from [`BidiChannelId`] to [`AfcId`]
impl From<BidiChannelId> for AfcId {
    fn from(value: BidiChannelId) -> Self {
        Self {
            id: *truncate(value.as_array()),
        }
    }
}

/// Convert from [`UniChannelId`] to [`AfcId`]
impl From<UniChannelId> for AfcId {
    fn from(value: UniChannelId) -> Self {
        Self {
            id: *truncate(value.as_array()),
        }
    }
}

/// Convert from [`Id`] to [`AfcId`]
impl From<Id> for AfcId {
    fn from(value: Id) -> Self {
        Self {
            id: *truncate(value.as_array()),
        }
    }
}

// serialized command which must be passed over AFC.
pub type AfcCtrl = Vec<Box<[u8]>>;

#[tarpc::service]
pub trait DaemonApi {
    async fn initialize() -> Result<()>;

    /// Gets local address the Aranya sync server is bound to.
    async fn aranya_local_addr() -> Result<SocketAddr>;

    /// Gets the public key bundle for this device
    async fn get_key_bundle() -> Result<KeyBundle>;

    /// Gets the public device id.
    async fn get_device_id() -> Result<DeviceId>;

    /// Adds the peer for automatic periodic syncing.
    async fn add_sync_peer(addr: Addr, team: TeamId, interval: Duration) -> Result<()>;

    /// Removes the peer from automatic syncing.
    async fn remove_sync_peer(addr: Addr, team: TeamId) -> Result<()>;

    /// add a team to the local device store that was created by someone else. Not an aranya action/command.
    async fn add_team(team: TeamId) -> Result<()>;

    /// remove a team from the local device store.
    async fn remove_team(team: TeamId) -> Result<()>;

    /// Create a new graph/team with the current device as the owner.
    async fn create_team() -> Result<TeamId>;
    async fn close_team(team: TeamId) -> Result<()>;

    async fn add_device_to_team(team: TeamId, keys: KeyBundle) -> Result<()>;
    async fn remove_device_from_team(team: TeamId, device: DeviceId) -> Result<()>;

    async fn assign_role(team: TeamId, device: DeviceId, role: Role) -> Result<()>;
    async fn revoke_role(team: TeamId, device: DeviceId, role: Role) -> Result<()>;

    async fn assign_net_name(team: TeamId, device: DeviceId, name: NetIdentifier) -> Result<()>;
    async fn remove_net_name(team: TeamId, device: DeviceId, name: NetIdentifier) -> Result<()>;

    async fn create_label(team: TeamId, label: Label) -> Result<()>;
    async fn delete_label(team: TeamId, label: Label) -> Result<()>;

    async fn assign_label(team: TeamId, device: DeviceId, label: Label) -> Result<()>;
    async fn revoke_label(team: TeamId, device: DeviceId, label: Label) -> Result<()>;

    async fn create_channel(
        team: TeamId,
        peer: NetIdentifier,
        node_id: NodeId,
        label: Label,
    ) -> Result<(AfcId, AfcCtrl)>;
    async fn delete_channel(chan: AfcId) -> Result<AfcCtrl>;
    async fn receive_afc_ctrl(
        team: TeamId,
        node_id: NodeId,
        ctrl: AfcCtrl,
    ) -> Result<(AfcId, Label)>;
}
