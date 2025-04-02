#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::{fmt, hash::Hash, net::SocketAddr, time::Duration};
use std::path::PathBuf;

use aranya_aqc_util::{
    BidiChannelCreated, BidiChannelReceived, BidiKeyId, Label as AqcLabel, UniChannelCreated,
    UniChannelReceived, UniKeyId,
};
use aranya_crypto::{
    afc::{BidiChannelId as AfcBidiChannelId, UniChannelId as AfcUniChannelId},
    aqc::{BidiChannelId as AqcBidiChannelId, UniChannelId as AqcUniChannelId},
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

/// A device's public key bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Uniquely identifies an AQC channel.
///
/// It is a [`AqcBidiChannelId`] or [`AqcUniChannelId`] truncated to
/// 128 bits.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AqcId([u8; 16]);

impl fmt::Display for AqcId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_base58())
    }
}

/// Convert from [`BidiChannelId`] to [`AqcId`]
impl From<AqcBidiChannelId> for AqcId {
    fn from(value: AqcBidiChannelId) -> Self {
        Self(*truncate(value.as_array()))
    }
}

/// Convert from [`UniChannelId`] to [`AqcId`]
impl From<AqcUniChannelId> for AqcId {
    fn from(value: AqcUniChannelId) -> Self {
        Self(*truncate(value.as_array()))
    }
}

/// Convert from [`Id`] to [`AqcId`]
impl From<Id> for AqcId {
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
// TODO: move AqcId into this type
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AqcBidiChannelCreatedInfo {
    pub parent_cmd_id: Id,
    pub author_id: DeviceId,
    pub author_enc_key_id: EncryptionKeyId,
    pub peer_id: DeviceId,
    pub peer_enc_pk: Vec<u8>,
    pub label: AqcLabel,
    pub key_id: BidiKeyId,
}

/// Convert from [`AqcBidiChannelCreated`] to [`AqcChannelCreatedInfo`]
impl From<BidiChannelCreated<'_>> for AqcChannelInfo {
    fn from(e: BidiChannelCreated<'_>) -> Self {
        Self::BidiCreated(AqcBidiChannelCreatedInfo {
            parent_cmd_id: e.parent_cmd_id,
            author_id: DeviceId(e.author_id.into()),
            author_enc_key_id: e.author_enc_key_id,
            peer_id: DeviceId(e.peer_id.into()),
            peer_enc_pk: e.peer_enc_pk.into(),
            label: AqcLabel::new(e.label.into()),
            key_id: e.key_id,
        })
    }
}

/// Bidirectional AQC channel info.
// TODO: move AqcId into this type
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AqcBidiChannelReceivedInfo {
    pub parent_cmd_id: Id,
    pub author_id: DeviceId,
    pub peer_enc_key_id: EncryptionKeyId,
    pub peer_id: DeviceId,
    pub author_enc_pk: Vec<u8>,
    pub label: AqcLabel,
    pub encap: Vec<u8>,
}

/// Convert from [`AqcBidiChannelReceived`] to [`AqcChannelReceivedInfo`]
impl From<BidiChannelReceived<'_>> for AqcChannelInfo {
    fn from(e: BidiChannelReceived<'_>) -> Self {
        Self::BidiReceived(AqcBidiChannelReceivedInfo {
            parent_cmd_id: e.parent_cmd_id,
            author_id: DeviceId(e.author_id.into()),
            peer_enc_key_id: e.peer_enc_key_id,
            peer_id: DeviceId(e.peer_id.into()),
            author_enc_pk: e.author_enc_pk.into(),
            label: AqcLabel::new(e.label.into()),
            encap: e.encap.to_vec(),
        })
    }
}

/// Unidirectional AQC channel info.
// TODO: move AqcId into this type
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AqcUniChannelCreatedInfo {
    pub parent_cmd_id: Id,
    pub author_id: DeviceId,
    pub send_id: DeviceId,
    pub recv_id: DeviceId,
    pub author_enc_key_id: EncryptionKeyId,
    pub peer_enc_pk: Vec<u8>,
    pub label: AqcLabel,
    pub key_id: UniKeyId,
}

/// Convert from [`AqcUniChannelCreated`] to [`AqcChannelInfo`]
impl From<UniChannelCreated<'_>> for AqcChannelInfo {
    fn from(e: UniChannelCreated<'_>) -> Self {
        Self::UniCreated(AqcUniChannelCreatedInfo {
            parent_cmd_id: e.parent_cmd_id,
            author_id: DeviceId(e.author_id.into()),
            send_id: DeviceId(e.send_id.into()),
            recv_id: DeviceId(e.recv_id.into()),
            author_enc_key_id: e.author_enc_key_id,
            peer_enc_pk: e.peer_enc_pk.into(),
            label: AqcLabel::new(e.label.into()),
            key_id: e.key_id,
        })
    }
}

/// Unidirectional AQC channel info.
// TODO: move AqcId into this type
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AqcUniChannelReceivedInfo {
    pub parent_cmd_id: Id,
    pub author_id: DeviceId,
    pub send_id: DeviceId,
    pub recv_id: DeviceId,
    pub author_enc_pk: Vec<u8>,
    pub peer_enc_key_id: EncryptionKeyId,
    pub label: AqcLabel,
    pub encap: Vec<u8>,
}

/// Convert from [`AqcUniChannelReceived`] to [`AqcChannelInfo`]
impl From<UniChannelReceived<'_>> for AqcChannelInfo {
    fn from(e: UniChannelReceived<'_>) -> Self {
        Self::UniReceived(AqcUniChannelReceivedInfo {
            parent_cmd_id: e.parent_cmd_id,
            author_id: DeviceId(e.author_id.into()),
            send_id: DeviceId(e.send_id.into()),
            recv_id: DeviceId(e.recv_id.into()),
            author_enc_pk: e.author_enc_pk.into(),
            peer_enc_key_id: e.peer_enc_key_id,
            label: AqcLabel::new(e.label.into()),
            encap: e.encap.to_vec(),
        })
    }
}

/// Information needed to use the key store.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]

pub struct KeyStoreInfo {
    /// Path of the key store.
    pub path: PathBuf,
    /// Path of the wrapped key.
    pub wrapped_key: PathBuf,
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
    async fn add_sync_peer(addr: Addr, team: TeamId, interval: Duration) -> Result<()>;

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

    /// Assign an AFC network identifier to a device.
    async fn assign_afc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;
    /// Remove an AFC network identifier from a device.
    async fn remove_afc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;

    /// Assign an AQC network identifier to a device.
    async fn assign_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;
    /// Remove an AQC network identifier from a device.
    async fn remove_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;

    /// Create a fast channels label.
    async fn create_label(team: TeamId, label: AfcLabel) -> Result<()>;
    /// Delete a fast channels label.
    async fn delete_label(team: TeamId, label: AfcLabel) -> Result<()>;

    /// Assign a fast channels label to a device.
    async fn assign_label(team: TeamId, device: DeviceId, label: AfcLabel) -> Result<()>;
    /// Revoke a fast channels label from a device.
    async fn revoke_label(team: TeamId, device: DeviceId, label: AfcLabel) -> Result<()>;
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
        label: AfcLabel,
    ) -> Result<(AqcId, AqcCtrl, AqcChannelInfo)>;
    /// Create a unidirectional QUIC channel.
    async fn create_aqc_uni_channel(
        team: TeamId,
        peer: NetIdentifier,
        node_id: NodeId,
        label: AfcLabel,
    ) -> Result<(AqcId, AqcCtrl, AqcChannelInfo)>;
    /// Delete a QUIC channel.
    async fn delete_aqc_channel(chan: AqcId) -> Result<AqcCtrl>;
    /// Receive AQC ctrl message.
    async fn receive_aqc_ctrl(
        team: TeamId,
        node_id: NodeId,
        ctrl: AqcCtrl,
    ) -> Result<(AqcId, NetIdentifier, AqcChannelInfo)>;
    /// Query devices on team.
    async fn query_devices_on_team(team: TeamId) -> Result<Vec<DeviceId>>;
    /// Query device role.
    async fn query_device_role(team: TeamId, device: DeviceId) -> Result<Role>;
    /// Query device keybundle.
    async fn query_device_keybundle(team: TeamId, device: DeviceId) -> Result<KeyBundle>;
    /// Query device label assignments.
    async fn query_device_label_assignments(
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
    /// Query label exists.
    async fn query_label_exists(team: TeamId, label: AfcLabel) -> Result<bool>;
}
