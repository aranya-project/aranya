//! This code is @generated by `policy-ifgen`. DO NOT EDIT.
#![allow(clippy::duplicated_attributes)]
#![allow(clippy::enum_variant_names)]
#![allow(missing_docs)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
extern crate alloc;
use alloc::vec::Vec;
use aranya_policy_ifgen::{
    macros::{actions, effect, effects, value},
    ClientError, Id, Value, Text,
};
/// KeyBundle policy struct.
#[value]
pub struct KeyBundle {
    pub ident_key: Vec<u8>,
    pub sign_key: Vec<u8>,
    pub enc_key: Vec<u8>,
}
/// Role policy enum.
#[value]
pub enum Role {
    Owner,
    Admin,
    Operator,
    Member,
}
/// ChanOp policy enum.
#[value]
pub enum ChanOp {
    RecvOnly,
    SendOnly,
    SendRecv,
}
/// Enum of policy effects that can occur in response to a policy action.
#[effects]
pub enum Effect {
    TeamCreated(TeamCreated),
    TeamTerminated(TeamTerminated),
    MemberAdded(MemberAdded),
    MemberRemoved(MemberRemoved),
    OwnerAssigned(OwnerAssigned),
    AdminAssigned(AdminAssigned),
    OperatorAssigned(OperatorAssigned),
    OwnerRevoked(OwnerRevoked),
    AdminRevoked(AdminRevoked),
    OperatorRevoked(OperatorRevoked),
    AqcNetworkNameSet(AqcNetworkNameSet),
    AqcNetworkNameUnset(AqcNetworkNameUnset),
    AqcBidiChannelCreated(AqcBidiChannelCreated),
    AqcBidiChannelReceived(AqcBidiChannelReceived),
    AqcUniChannelCreated(AqcUniChannelCreated),
    AqcUniChannelReceived(AqcUniChannelReceived),
    LabelCreated(LabelCreated),
    LabelDeleted(LabelDeleted),
    LabelAssigned(LabelAssigned),
    LabelRevoked(LabelRevoked),
    QueryLabelExistsResult(QueryLabelExistsResult),
    QueriedLabel(QueriedLabel),
    QueriedLabelAssignment(QueriedLabelAssignment),
    QueryDevicesOnTeamResult(QueryDevicesOnTeamResult),
    QueryDeviceRoleResult(QueryDeviceRoleResult),
    QueryDeviceKeyBundleResult(QueryDeviceKeyBundleResult),
    QueryAqcNetIdentifierResult(QueryAqcNetIdentifierResult),
    QueryAqcNetworkNamesOutput(QueryAqcNetworkNamesOutput),
}
/// TeamCreated policy effect.
#[effect]
pub struct TeamCreated {
    pub owner_id: Id,
}
/// TeamTerminated policy effect.
#[effect]
pub struct TeamTerminated {
    pub owner_id: Id,
}
/// MemberAdded policy effect.
#[effect]
pub struct MemberAdded {
    pub device_id: Id,
    pub device_keys: KeyBundle,
}
/// MemberRemoved policy effect.
#[effect]
pub struct MemberRemoved {
    pub device_id: Id,
}
/// OwnerAssigned policy effect.
#[effect]
pub struct OwnerAssigned {
    pub device_id: Id,
}
/// AdminAssigned policy effect.
#[effect]
pub struct AdminAssigned {
    pub device_id: Id,
}
/// OperatorAssigned policy effect.
#[effect]
pub struct OperatorAssigned {
    pub device_id: Id,
}
/// OwnerRevoked policy effect.
#[effect]
pub struct OwnerRevoked {
    pub device_id: Id,
}
/// AdminRevoked policy effect.
#[effect]
pub struct AdminRevoked {
    pub device_id: Id,
}
/// OperatorRevoked policy effect.
#[effect]
pub struct OperatorRevoked {
    pub device_id: Id,
}
/// AqcNetworkNameSet policy effect.
#[effect]
pub struct AqcNetworkNameSet {
    pub device_id: Id,
    pub net_identifier: Text,
}
/// AqcNetworkNameUnset policy effect.
#[effect]
pub struct AqcNetworkNameUnset {
    pub device_id: Id,
}
/// AqcBidiChannelCreated policy effect.
#[effect]
pub struct AqcBidiChannelCreated {
    pub channel_id: Id,
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub author_enc_key_id: Id,
    pub peer_id: Id,
    pub peer_enc_pk: Vec<u8>,
    pub label_id: Id,
    pub author_secrets_id: Id,
    pub psk_length_in_bytes: i64,
}
/// AqcBidiChannelReceived policy effect.
#[effect]
pub struct AqcBidiChannelReceived {
    pub channel_id: Id,
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub author_enc_pk: Vec<u8>,
    pub peer_id: Id,
    pub peer_enc_key_id: Id,
    pub label_id: Id,
    pub encap: Vec<u8>,
    pub psk_length_in_bytes: i64,
}
/// AqcUniChannelCreated policy effect.
#[effect]
pub struct AqcUniChannelCreated {
    pub channel_id: Id,
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub sender_id: Id,
    pub receiver_id: Id,
    pub author_enc_key_id: Id,
    pub peer_enc_pk: Vec<u8>,
    pub label_id: Id,
    pub author_secrets_id: Id,
    pub psk_length_in_bytes: i64,
}
/// AqcUniChannelReceived policy effect.
#[effect]
pub struct AqcUniChannelReceived {
    pub channel_id: Id,
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub sender_id: Id,
    pub receiver_id: Id,
    pub author_enc_pk: Vec<u8>,
    pub peer_enc_key_id: Id,
    pub label_id: Id,
    pub encap: Vec<u8>,
    pub psk_length_in_bytes: i64,
}
/// LabelCreated policy effect.
#[effect]
pub struct LabelCreated {
    pub label_id: Id,
    pub label_name: Text,
    pub label_author_id: Id,
}
/// LabelDeleted policy effect.
#[effect]
pub struct LabelDeleted {
    pub label_name: Text,
    pub label_author_id: Id,
    pub label_id: Id,
    pub author_id: Id,
}
/// LabelAssigned policy effect.
#[effect]
pub struct LabelAssigned {
    pub label_id: Id,
    pub label_name: Text,
    pub label_author_id: Id,
    pub author_id: Id,
}
/// LabelRevoked policy effect.
#[effect]
pub struct LabelRevoked {
    pub label_id: Id,
    pub label_name: Text,
    pub label_author_id: Id,
    pub author_id: Id,
}
/// QueryLabelExistsResult policy effect.
#[effect]
pub struct QueryLabelExistsResult {
    pub label_id: Id,
    pub label_name: Text,
    pub label_author_id: Id,
}
/// QueriedLabel policy effect.
#[effect]
pub struct QueriedLabel {
    pub label_id: Id,
    pub label_name: Text,
    pub label_author_id: Id,
}
/// QueriedLabelAssignment policy effect.
#[effect]
pub struct QueriedLabelAssignment {
    pub device_id: Id,
    pub label_id: Id,
    pub label_name: Text,
    pub label_author_id: Id,
}
/// QueryDevicesOnTeamResult policy effect.
#[effect]
pub struct QueryDevicesOnTeamResult {
    pub device_id: Id,
}
/// QueryDeviceRoleResult policy effect.
#[effect]
pub struct QueryDeviceRoleResult {
    pub role: Role,
}
/// QueryDeviceKeyBundleResult policy effect.
#[effect]
pub struct QueryDeviceKeyBundleResult {
    pub device_keys: KeyBundle,
}
/// QueryAqcNetIdentifierResult policy effect.
#[effect]
pub struct QueryAqcNetIdentifierResult {
    pub net_identifier: Text,
}
/// QueryAqcNetworkNamesOutput policy effect.
#[effect]
pub struct QueryAqcNetworkNamesOutput {
    pub net_identifier: Text,
    pub device_id: Id,
}
/// Implements all supported policy actions.
#[actions]
pub trait ActorExt {
    fn create_team(
        &mut self,
        owner_keys: KeyBundle,
        nonce: Vec<u8>,
    ) -> Result<(), ClientError>;
    fn terminate_team(&mut self) -> Result<(), ClientError>;
    fn add_member(&mut self, device_keys: KeyBundle) -> Result<(), ClientError>;
    fn remove_member(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn assign_role(&mut self, device_id: Id, role: Role) -> Result<(), ClientError>;
    fn revoke_role(&mut self, device_id: Id, role: Role) -> Result<(), ClientError>;
    fn set_aqc_network_name(
        &mut self,
        device_id: Id,
        net_identifier: Text,
    ) -> Result<(), ClientError>;
    fn unset_aqc_network_name(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn create_aqc_bidi_channel(
        &mut self,
        peer_id: Id,
        label_id: Id,
    ) -> Result<(), ClientError>;
    fn create_aqc_uni_channel(
        &mut self,
        sender_id: Id,
        receiver_id: Id,
        label_id: Id,
    ) -> Result<(), ClientError>;
    fn create_label(&mut self, name: Text) -> Result<(), ClientError>;
    fn delete_label(&mut self, label_id: Id) -> Result<(), ClientError>;
    fn assign_label(
        &mut self,
        device_id: Id,
        label_id: Id,
        op: ChanOp,
    ) -> Result<(), ClientError>;
    fn revoke_label(&mut self, device_id: Id, label_id: Id) -> Result<(), ClientError>;
    fn query_label_exists(&mut self, label_id: Id) -> Result<(), ClientError>;
    fn query_labels(&mut self) -> Result<(), ClientError>;
    fn query_label_assignments(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn query_devices_on_team(&mut self) -> Result<(), ClientError>;
    fn query_device_role(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn query_device_keybundle(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn query_aqc_net_identifier(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn query_aqc_network_names(&mut self) -> Result<(), ClientError>;
}
