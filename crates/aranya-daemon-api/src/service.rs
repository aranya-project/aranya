#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

//! Defines the common API service interface between the Aranya client and daemon.
//!
//! This module contains the types and methods that compose the daemon API interface.
//! The daemon acts as the server, and the client consumes this API. RPC calls are defined
//! using a Rust trait to ensure the client and daemon implement the same methods.

use core::{fmt, hash::Hash, net::SocketAddr, time::Duration};
use std::path::PathBuf;

use aranya_crypto::{
    aqc::{self, BidiAuthorSecretId, UniAuthorSecretId},
    custom_id,
    default::DefaultCipherSuite,
    EncryptionKeyId, Id,
};
use aranya_fast_channels::NodeId;
use aranya_util::Addr;
use serde::{Deserialize, Serialize};
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
///
/// This structure contains the public keys needed for cryptographic operations
/// when communicating with a device, including identity verification, signature
/// verification, message encryption, and data integrity.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
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

/// A configuration for creating or adding a team to a daemon.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamConfig {
    // TODO(nikki): any fields added to this should be public
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

// serialized command which must be passed over AQC.
pub type AqcCtrl = Vec<Box<[u8]>>;

/// AQC channel info.
/// This includes information that can be used to:
/// - Lookup the AQC PSK secret from the key store.
/// - Decode the PSK encap to derive the PSK.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum AqcChannelInfo {
    BidiCreated(AqcBidiChannelCreatedInfo),
    BidiReceived(AqcBidiChannelReceivedInfo),
    UniCreated(AqcUniChannelCreatedInfo),
    UniReceived(AqcUniChannelReceivedInfo),
}

/// Bidirectional AQC channel info.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AqcBidiChannelCreatedInfo {
    pub parent_cmd_id: Id,
    pub author_id: DeviceId,
    pub author_enc_key_id: EncryptionKeyId,
    pub peer_id: DeviceId,
    pub peer_enc_pk: Vec<u8>,
    pub label_id: LabelId,
    pub channel_id: aqc::BidiChannelId,
    pub author_secrets_id: BidiAuthorSecretId,
    pub psk_length_in_bytes: u16,
}

/// Bidirectional AQC channel info.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AqcBidiChannelReceivedInfo {
    pub parent_cmd_id: Id,
    pub author_id: DeviceId,
    pub peer_enc_key_id: EncryptionKeyId,
    pub peer_id: DeviceId,
    pub author_enc_pk: Vec<u8>,
    pub label_id: LabelId,
    pub encap: Vec<u8>,
    pub psk_length_in_bytes: u16,
}

/// Unidirectional AQC channel info.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AqcUniChannelCreatedInfo {
    pub parent_cmd_id: Id,
    pub author_id: DeviceId,
    pub send_id: DeviceId,
    pub recv_id: DeviceId,
    pub author_enc_key_id: EncryptionKeyId,
    pub peer_enc_pk: Vec<u8>,
    pub label_id: LabelId,
    pub channel_id: aqc::UniChannelId,
    pub author_secrets_id: UniAuthorSecretId,
    pub psk_length_in_bytes: u16,
}

/// Unidirectional AQC channel info.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AqcUniChannelReceivedInfo {
    pub parent_cmd_id: Id,
    pub author_id: DeviceId,
    pub send_id: DeviceId,
    pub recv_id: DeviceId,
    pub author_enc_pk: Vec<u8>,
    pub peer_enc_key_id: EncryptionKeyId,
    pub label_id: LabelId,
    pub encap: Vec<u8>,
    pub psk_length_in_bytes: u16,
}

/// Information needed to use the key store.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]

pub struct KeyStoreInfo {
    /// Path of the key store.
    pub path: PathBuf,
    /// Path of the wrapped key.
    pub wrapped_key: PathBuf,
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

/// A label, used to control access to channels.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Label {
    /// The ID of the label
    pub id: LabelId,
    /// The friendly name given to the label
    pub name: String,
}

/// The Daemon API trait defining the RPC interface.
///
/// This trait defines all the methods that can be called remotely by the Aranya client
/// to interact with the Aranya daemon. The daemon implements this trait to provide
/// the actual functionality, while the client uses this interface to make requests.
#[tarpc::service]
pub trait DaemonApi {
    /// Gets the key store info.
    /// The keystore can be used to pass private keys and secrets between the client and daemon.
    async fn get_keystore_info() -> Result<KeyStoreInfo>;

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
    /// - `config` - The [`SyncPeerConfig`] used to configure the sync peer.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the peer cannot be added.
    async fn add_sync_peer(addr: Addr, team: TeamId, config: SyncPeerConfig) -> Result<()>;

    /// Sync with peer immediately.
    ///
    /// # Parameters
    /// - `addr` - The network address of the peer to sync with.
    /// - `team` - The team ID that this syncing relationship belongs to.
    /// - `config` - An optional [`SyncPeerConfig`] used to configure the sync peer.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the sync fails.
    async fn sync_now(addr: Addr, team: TeamId, cfg: Option<SyncPeerConfig>) -> Result<()>;

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
    /// - `cfg` - The configuration of the team to add.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the team cannot be added.
    async fn add_team(team: TeamId, cfg: TeamConfig) -> Result<()>;

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
    /// # Parameters
    /// - `cfg` - The configuration of the team to create.
    ///
    /// # Returns
    /// - `Result<TeamId>` - The ID of the newly created team on success, or an error if the team cannot be created.
    async fn create_team(cfg: TeamConfig) -> Result<TeamId>;

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

    /// Creates a label.
    ///
    /// Labels are used to categorize and control access to channels.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `name` - The name of the label to create.
    ///
    /// # Returns
    /// - `Result<LabelId>` - The ID of the created label or an error if
    /// the label cannot be created.
    async fn create_label(team: TeamId, name: String) -> Result<LabelId>;

    /// Deletes a label.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `label_id` - The label to delete.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the label cannot be deleted.
    async fn delete_label(team: TeamId, label_id: LabelId) -> Result<()>;

    /// Assigns a label to a device.
    ///
    /// Gives a device access to create or participate in channels with
    /// the specified label.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `device` - The ID of the device to assign the label to.
    /// - `label_id` - The label to assign.
    /// - `op` - The type of operations allowed on this label by the given device.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the label cannot be assigned.
    async fn assign_label(
        team: TeamId,
        device: DeviceId,
        label_id: LabelId,
        op: ChanOp,
    ) -> Result<()>;

    /// Revokes a label from a device.
    ///
    /// Removes a device's access to channels with the specified label. When a
    /// user has their permissions revoked to use a label, all channels
    /// they are a member of that use that label are closed.
    ///
    /// # Parameters
    /// - `team` - The ID of the team.
    /// - `device` - The ID of the device to revoke the label from.
    /// - `label_id` - The label to revoke.
    ///
    /// # Returns
    /// - `Result<()>` - Success or an error if the label cannot be revoked.
    async fn revoke_label(team: TeamId, device: DeviceId, label_id: LabelId) -> Result<()>;

    /// Create a bidirectional QUIC channel.
    async fn create_aqc_bidi_channel(
        team: TeamId,
        peer: NetIdentifier,
        node_id: NodeId,
        label_id: LabelId,
    ) -> Result<(AqcCtrl, AqcChannelInfo)>;
    /// Create a unidirectional QUIC channel.
    async fn create_aqc_uni_channel(
        team: TeamId,
        peer: NetIdentifier,
        node_id: NodeId,
        label_id: LabelId,
    ) -> Result<(AqcCtrl, AqcChannelInfo)>;
    /// Delete a QUIC bidi channel.
    async fn delete_aqc_bidi_channel(chan: AqcBidiChannelId) -> Result<AqcCtrl>;
    /// Delete a QUIC uni channel.
    async fn delete_aqc_uni_channel(chan: AqcUniChannelId) -> Result<AqcCtrl>;
    /// Receive AQC ctrl message.
    async fn receive_aqc_ctrl(
        team: TeamId,
        node_id: NodeId,
        ctrl: AqcCtrl,
    ) -> Result<(NetIdentifier, AqcChannelInfo)>;

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
