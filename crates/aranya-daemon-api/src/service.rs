#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::{fmt, hash::Hash, net::SocketAddr, time::Duration};
use std::path::PathBuf;

use aranya_crypto::{
    afc::{BidiChannelId as AfcBidiChannelId, UniChannelId as AfcUniChannelId},
    aqc::{self, BidiAuthorSecretId, UniAuthorSecretId},
    custom_id,
    default::DefaultCipherSuite,
    EncryptionKeyId, Id,
};
use aranya_fast_channels::{Label as AfcLabel, NodeId};
use aranya_util::Addr;
use serde::{Deserialize, Serialize};
use spideroak_base58::ToBase58;
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
/// It is a [`AfcBidiChannelId`] or [`AfcUniChannelId`] truncated to
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

/// Convert from [`AfcBidiChannelId`] to [`AfcId`]
impl From<AfcBidiChannelId> for AfcId {
    fn from(value: AfcBidiChannelId) -> Self {
        Self(*truncate(value.as_array()))
    }
}

/// Convert from [`AfcUniChannelId`] to [`AfcId`]
impl From<AfcUniChannelId> for AfcId {
    fn from(value: AfcUniChannelId) -> Self {
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

/// A label.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Label {
    pub id: LabelId,
    pub name: String,
}

#[tarpc::service]
pub trait DaemonApi {
    /// Gets the key store info.
    /// The keystore can be used to pass private keys and secrets between the client and daemon.
    async fn get_keystore_info() -> Result<KeyStoreInfo>;

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

    /// Create an AFC label.
    async fn create_afc_label(team: TeamId, label: AfcLabel) -> Result<()>;
    /// Delete an AFC label.
    async fn delete_afc_label(team: TeamId, label: AfcLabel) -> Result<()>;
    /// Assign a fast channels label to a device.
    async fn assign_afc_label(team: TeamId, device: DeviceId, label: AfcLabel) -> Result<()>;
    /// Revoke a fast channels label from a device.
    async fn revoke_afc_label(team: TeamId, device: DeviceId, label: AfcLabel) -> Result<()>;

    /// Assign a fast channels network identifier to a device.
    async fn assign_afc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;
    /// Remove a fast channels network identifier from a device.
    async fn remove_afc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;

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

    /// Create a fast channel.
    async fn create_afc_bidi_channel(
        team: TeamId,
        peer: NetIdentifier,
        node_id: NodeId,
        label: AfcLabel,
    ) -> Result<(AfcId, AfcCtrl)>;
    /// Delete a fast channel.
    async fn delete_afc_channel(chan: AfcId) -> Result<AfcCtrl>;
    /// Receive a fast channel ctrl message.
    async fn receive_afc_ctrl(
        team: TeamId,
        node_id: NodeId,
        ctrl: AfcCtrl,
    ) -> Result<(AfcId, NetIdentifier, AfcLabel)>;

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
    async fn delete_aqc_bidi_channel(key_id: BidiAuthorSecretId) -> Result<()>;
    /// Delete a QUIC uni channel.
    async fn delete_aqc_uni_channel(key_id: UniAuthorSecretId) -> Result<()>;
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
    /// Query device AFC label assignments.
    async fn query_device_afc_label_assignments(
        team: TeamId,
        device: DeviceId,
    ) -> Result<Vec<AfcLabel>>;
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
    // Query labels on team.
    async fn query_labels(team: TeamId) -> Result<Vec<Label>>;
    /// Query whether a label exists.
    async fn query_label_exists(team: TeamId, label: LabelId) -> Result<bool>;
    /// Query whether an AFC label exists.
    async fn query_afc_label_exists(team: TeamId, label: AfcLabel) -> Result<bool>;
}
