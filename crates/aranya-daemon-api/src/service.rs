#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

//! Defines the common API service interface between the Aranya client and daemon.
//!
//! This module contains the types and methods that compose the daemon API interface.
//! The daemon acts as the server, and the client consumes this API. RPC calls are defined
//! using a Rust trait to ensure the client and daemon implement the same methods.

use core::{fmt, hash::Hash, net::SocketAddr, time::Duration};

use aranya_crypto::{
    afc::{BidiChannelId, UniChannelId},
    custom_id,
    default::DefaultCipherSuite,
    Id,
};
use aranya_fast_channels::{Label, NodeId};
use aranya_util::Addr;
use serde::{Deserialize, Serialize};
use spideroak_base58::ToBase58;
use tracing::error;

/// Cipher Suite type alias for the cryptographic operations used in the daemon API.
///
/// This type represents the default cipher suite used for cryptographic operations
/// throughout the Aranya system.
pub type CS = DefaultCipherSuite;

/// An error returned by the API.
///
/// This error type encapsulates various error conditions that can occur when
/// interacting with the daemon API. It provides a string representation of the error.
///
// TODO: enum for errors?
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

/// Result type used throughout the daemon API.
///
/// This type alias simplifies error handling by using the API's [`Error`] type
/// as the default error type.
pub type Result<T, E = Error> = core::result::Result<T, E>;

custom_id! {
    /// The Device ID.
    ///
    /// A unique identifier for an Aranya device within the system.
    /// This ID is used to reference specific devices when performing operations
    /// such as adding devices to teams or assigning roles.
    pub struct DeviceId;
}

custom_id! {
    /// The Team ID (a.k.a Graph ID).
    ///
    /// A unique identifier for a team of devices in Aranya.
    /// Teams represent a group of devices that can collaborate and communicate
    /// with each other securely.
    pub struct TeamId;
}

/// A device's public key bundle.
///
/// This structure contains the public keys needed for cryptographic operations
/// when communicating with a device, including identity verification, signature
/// verification, message encryption, and data integrity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBundle {
    /// The identity public key used to verify the device's identity
    pub identity: Vec<u8>,

    /// The signing public key used to verify the device's signature
    pub signing: Vec<u8>,

    /// The encryption public key used for message encryption
    pub encryption: Vec<u8>,
}

/// A device's role on the team.
///
/// Roles determine what permissions a device has within a team.
/// Different roles have different capabilities regarding team management
/// and access control. For a more detailed permissions breakdown, see `aranya-daemon/src/policy.md`.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum Role {
    /// Owner role has full control over the team and can perform all operations
    Owner,

    /// Admin role can manage devices and their permissions
    Admin,

    /// Operator role is more privileged and can manage members
    Operator,

    /// Member role has basic access to team resources like using AFC channels
    Member,
}

/// A device's network identifier.
///
/// This identifier is used for networking purposes to uniquely identify
/// a device on the network when establishing connections.
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
/// 128 bits. This identifier is used to reference specific Aranya Fast Channels
/// when performing operations such as sending messages or managing channel state.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AfcId([u8; 16]);

impl fmt::Display for AfcId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_base58())
    }
}

// Helper function to truncate a larger array to a smaller one.
//
// This function is used internally to convert between different ID types
// when creating an [`AfcId`] from other ID types.
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

/// Serialized command which must be passed over AFC.
///
/// This type represents control messages sent through Aranya Fast Channels
/// to manage channel state and operations.
pub type AfcCtrl = Vec<Box<[u8]>>;

/// The Daemon API trait defining the RPC interface.
///
/// This trait defines all the methods that can be called remotely by the Aranya client
/// to interact with the Aranya daemon. The daemon implements this trait to provide
/// the actual functionality, while the client uses this interface to make requests.
#[tarpc::service]
pub trait DaemonApi {
    /// Gets local address the Aranya sync server is bound to.
    ///
    /// Returns the socket address that the local Aranya sync server is listening on.
    /// This is useful for clients that need to establish direct connections to the server.
    ///
    /// # Returns
    /// - `Result<SocketAddr>` - The local socket address on success, or an error if the address cannot be determined.
    async fn aranya_local_addr() -> Result<SocketAddr>;

    /// Gets the public key bundle for this device.
    ///
    /// Retrieves the public cryptographic keys associated with the local device.
    /// These keys are used for identification, authentication, and encryption.
    ///
    /// # Returns
    /// - `Result<KeyBundle>` - The device's public key bundle on success, or an error if the keys cannot be retrieved.
    async fn get_key_bundle() -> Result<KeyBundle>;

    /// Gets the public device id.
    ///
    /// Retrieves the unique identifier for the local device.
    ///
    /// # Returns
    /// - `Result<DeviceId>` - The device's ID on success, or an error if the ID cannot be retrieved.
    async fn get_device_id() -> Result<DeviceId>;

    /// Adds the peer for automatic periodic syncing.
    ///
    /// Configures the daemon to periodically sync with the specified peer at the given interval.
    ///
    /// # Parameters
    /// - `addr` - The network address of the peer to sync with.
    /// - `team` - The team ID that this syncing relationship belongs to.
    /// - `interval` - How frequently to attempt synchronization with the peer.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the peer cannot be added.
    async fn add_sync_peer(addr: Addr, team: TeamId, interval: Duration) -> Result<()>;

    /// Removes the peer from automatic syncing.
    ///
    /// Stops periodic synchronization with the specified peer.
    ///
    /// # Parameters
    /// - `addr` - The network address of the peer to stop syncing with.
    /// - `team` - The team ID that this syncing relationship belongs to.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the peer cannot be removed.
    async fn remove_sync_peer(addr: Addr, team: TeamId) -> Result<()>;

    /// Adds a team to the local device store that was created by someone else.
    ///
    /// This is not an aranya action/command, but rather a local operation to
    /// keep track of teams the device is part of.
    ///
    /// # Parameters
    /// - `team` - The ID of the team to add.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the team cannot be added.
    async fn add_team(team: TeamId) -> Result<()>;

    /// Removes a team from the local device store.
    ///
    /// # Parameters
    /// - `team` - The ID of the team to remove.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the team cannot be removed.
    async fn remove_team(team: TeamId) -> Result<()>;

    /// Creates a new graph/team with the current device as the owner.
    ///
    /// Initializes a new team and assigns the current device as the owner.
    ///
    /// # Returns
    /// - `Result<TeamId>` - The ID of the newly created team on success, or an error if the team cannot be created.
    async fn create_team() -> Result<TeamId>;

    /// Closes the team so that it cannot be used anymore.
    ///
    /// Performs necessary cleanup operations when a team is no longer needed.
    ///
    /// # Parameters
    /// - `team` - The ID of the team to close.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the team cannot be closed.
    async fn close_team(team: TeamId) -> Result<()>;

    /// Adds a device to the team.
    ///
    /// # Parameters
    /// - `team` - The ID of the team to add the device to.
    /// - `keys` - The public key bundle of the device to add.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the device cannot be added.
    async fn add_device_to_team(team: TeamId, keys: KeyBundle) -> Result<()>;

    /// Removes a device from the team.
    ///
    /// # Parameters
    /// - `team` - The ID of the team to remove the device from.
    /// - `device` - The ID of the device to remove.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the device cannot be removed.
    async fn remove_device_from_team(team: TeamId, device: DeviceId) -> Result<()>;

    /// Assigns a role to a device.
    ///
    /// Sets the permission level for a device within a team.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `device` - The ID of the device to assign the role to.
    /// - `role` - The role to assign.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the role cannot be assigned.
    async fn assign_role(team: TeamId, device: DeviceId, role: Role) -> Result<()>;

    /// Revokes a role from a device.
    ///
    /// Removes a specific permission level from a device within a team.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `device` - The ID of the device to revoke the role from.
    /// - `role` - The role to revoke.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the role cannot be revoked.
    async fn revoke_role(team: TeamId, device: DeviceId, role: Role) -> Result<()>;

    /// Assign an AFC network identifier to a device.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `device` - The ID of the device to assign the identifier to.
    /// - `name` - The network identifier to assign.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the identifier cannot be assigned.
    async fn assign_afc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;

    /// Remove an AFC network identifier from a device.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `device` - The ID of the device to remove the identifier from.
    /// - `name` - The network identifier to remove.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the identifier cannot be removed.
    async fn remove_afc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;

    /// Assign a QUIC channels network identifier to a device.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `device` - The ID of the device to assign the identifier to.
    /// - `name` - The network identifier to assign.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the identifier cannot be assigned.
    async fn assign_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;

    /// Remove a QUIC channels network identifier from a device.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `device` - The ID of the device to remove the identifier from.
    /// - `name` - The network identifier to remove.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the identifier cannot be removed.
    async fn remove_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;

    /// Creates an Aranya Fast Channels label.
    ///
    /// Labels are used to categorize and control access to channels.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `label` - The label to create.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the label cannot be created.
    async fn create_label(team: TeamId, label: Label) -> Result<()>;

    /// Deletes a fast channels label.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `label` - The label to delete.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the label cannot be deleted.
    async fn delete_label(team: TeamId, label: Label) -> Result<()>;

    /// Assigns a label to a device.
    ///
    /// Gives a device access to create or participate in channels with
    /// the specified label.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `device` - The ID of the device to assign the label to.
    /// - `label` - The label to assign.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the label cannot be assigned.
    async fn assign_label(team: TeamId, device: DeviceId, label: Label) -> Result<()>;

    /// Revokes a label from a device.
    ///
    /// Removes a device's access to channels with the specified label. When a
    /// user has their permissions revoked to use a label, all channels
    /// they are a member of that use that label are closed.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `device` - The ID of the device to revoke the label from.
    /// - `label` - The label to revoke.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the label cannot be revoked.
    async fn revoke_label(team: TeamId, device: DeviceId, label: Label) -> Result<()>;

    /// Creates a fast channel.
    ///
    /// Establishes a bidirectional communication channel with a peer.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `peer` - The network identifier of the peer to create the channel with.
    /// - `node_id` - The node ID associated with the peer for this channel.
    /// - `label` - The label to associate with this channel.
    ///
    /// # Returns
    /// - `Result<(AfcId, AfcCtrl)>` - The channel ID and control message on success, or an error if the channel cannot be created.
    async fn create_afc_bidi_channel(
        team: TeamId,
        peer: NetIdentifier,
        node_id: NodeId,
        label: Label,
    ) -> Result<(AfcId, AfcCtrl)>;

    /// Deletes a fast channel.
    ///
    /// Tears down an existing communication channel.
    ///
    /// # Parameters
    /// - `chan` - The ID of the channel to delete.
    ///
    /// # Returns
    /// - `Result<AfcCtrl>` - The control message to send on success, or an error if the channel cannot be deleted.
    async fn delete_afc_channel(chan: AfcId) -> Result<AfcCtrl>;

    /// Receives a fast channel control message.
    ///
    /// Processes an incoming control message related to a fast channel.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `node_id` - The node ID associated with the peer that authored message.
    /// - `ctrl` - The control message to process.
    ///
    /// # Returns
    /// - `Result<(AfcId, NetIdentifier, Label)>` - The channel ID, peer identifier, and label on success,
    ///   or an error if the message cannot be processed.
    async fn receive_afc_ctrl(
        team: TeamId,
        node_id: NodeId,
        ctrl: AfcCtrl,
    ) -> Result<(AfcId, NetIdentifier, Label)>;
    /// Query devices on team.
    async fn query_devices_on_team(team: TeamId) -> Result<Vec<DeviceId>>;
    /// Query device role.
    async fn query_device_role(team: TeamId, device: DeviceId) -> Result<Role>;
    /// Query device keybundle.
    async fn query_device_keybundle(team: TeamId, device: DeviceId) -> Result<KeyBundle>;
    /// Query device label assignments.
    async fn query_device_label_assignments(team: TeamId, device: DeviceId) -> Result<Vec<Label>>;
    /// Query AFC network ID.
    async fn query_afc_net_identifier(
        team: TeamId,
        device: DeviceId,
    ) -> Result<Option<NetIdentifier>>;
    /// Query AQC network ID.
    async fn query_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
    ) -> Result<Option<NetIdentifier>>;
    /// Query label exists.
    async fn query_label_exists(team: TeamId, label: Label) -> Result<bool>;
}
