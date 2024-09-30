#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::time::Duration;
use std::fmt;

use crypto::custom_id;
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Addr(pub String);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Admin,
    Operator,
    Member,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetIdentifier(pub String);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct NodeId(pub u32);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Label(pub u32);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct ChannelId(pub [u8; 16]);

// serialized command which must be passed over APS.
pub type ApsCtrl = Vec<u8>;

#[tarpc::service]
pub trait DaemonApi {
    async fn initialize() -> Result<()>;

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
        label: Label,
    ) -> Result<(ChannelId, NodeId, ApsCtrl)>;
    async fn delete_channel(chan: ChannelId) -> Result<ApsCtrl>;
    async fn receive_aps_ctrl(ctrl: ApsCtrl) -> Result<()>;
}
