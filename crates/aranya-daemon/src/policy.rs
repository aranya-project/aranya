//! This code is @generated by `policy-ifgen`. DO NOT EDIT.
#![allow(clippy::duplicated_attributes)]
#![allow(clippy::enum_variant_names)]
#![allow(missing_docs)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
extern crate alloc;
use alloc::{string::String, vec::Vec};
use aranya_policy_ifgen::{
    macros::{actions, effect, effects, value},
    ClientError, Id, Value,
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
    ReadOnly,
    WriteOnly,
    ReadWrite,
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
    LabelDefined(LabelDefined),
    LabelUndefined(LabelUndefined),
    LabelAssigned(LabelAssigned),
    LabelRevoked(LabelRevoked),
    AfcNetworkNameSet(AfcNetworkNameSet),
    AfcNetworkNameUnset(AfcNetworkNameUnset),
    AqcNetworkNameSet(AqcNetworkNameSet),
    AqcNetworkNameUnset(AqcNetworkNameUnset),
    AfcBidiChannelCreated(AfcBidiChannelCreated),
    AfcBidiChannelReceived(AfcBidiChannelReceived),
    AfcUniChannelCreated(AfcUniChannelCreated),
    AfcUniChannelReceived(AfcUniChannelReceived),
    AqcBidiChannelCreated(AqcBidiChannelCreated),
    AqcBidiChannelReceived(AqcBidiChannelReceived),
    AqcUniChannelCreated(AqcUniChannelCreated),
    AqcUniChannelReceived(AqcUniChannelReceived),
    QueryDevicesOnTeamResult(QueryDevicesOnTeamResult),
    QueryDeviceRoleResult(QueryDeviceRoleResult),
    QueryDeviceKeyBundleResult(QueryDeviceKeyBundleResult),
    QueryDeviceLabelAssignmentsResult(QueryDeviceLabelAssignmentsResult),
    QueryAfcNetIdentifierResult(QueryAfcNetIdentifierResult),
    QueryAqcNetIdentifierResult(QueryAqcNetIdentifierResult),
    QueryLabelExistsResult(QueryLabelExistsResult),
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
/// LabelDefined policy effect.
#[effect]
pub struct LabelDefined {
    pub label: i64,
}
/// LabelUndefined policy effect.
#[effect]
pub struct LabelUndefined {
    pub label: i64,
}
/// LabelAssigned policy effect.
#[effect]
pub struct LabelAssigned {
    pub device_id: Id,
    pub label: i64,
    pub op: ChanOp,
}
/// LabelRevoked policy effect.
#[effect]
pub struct LabelRevoked {
    pub device_id: Id,
    pub label: i64,
}
/// AfcNetworkNameSet policy effect.
#[effect]
pub struct AfcNetworkNameSet {
    pub device_id: Id,
    pub net_identifier: String,
}
/// AfcNetworkNameUnset policy effect.
#[effect]
pub struct AfcNetworkNameUnset {
    pub device_id: Id,
}
/// AqcNetworkNameSet policy effect.
#[effect]
pub struct AqcNetworkNameSet {
    pub device_id: Id,
    pub net_identifier: String,
}
/// AqcNetworkNameUnset policy effect.
#[effect]
pub struct AqcNetworkNameUnset {
    pub device_id: Id,
}
/// AfcBidiChannelCreated policy effect.
#[effect]
pub struct AfcBidiChannelCreated {
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub author_enc_key_id: Id,
    pub peer_id: Id,
    pub peer_enc_pk: Vec<u8>,
    pub label: i64,
    pub channel_key_id: Id,
}
/// AfcBidiChannelReceived policy effect.
#[effect]
pub struct AfcBidiChannelReceived {
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub author_enc_pk: Vec<u8>,
    pub peer_id: Id,
    pub peer_enc_key_id: Id,
    pub label: i64,
    pub encap: Vec<u8>,
}
/// AfcUniChannelCreated policy effect.
#[effect]
pub struct AfcUniChannelCreated {
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub writer_id: Id,
    pub reader_id: Id,
    pub author_enc_key_id: Id,
    pub peer_enc_pk: Vec<u8>,
    pub label: i64,
    pub channel_key_id: Id,
}
/// AfcUniChannelReceived policy effect.
#[effect]
pub struct AfcUniChannelReceived {
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub writer_id: Id,
    pub reader_id: Id,
    pub author_enc_pk: Vec<u8>,
    pub peer_enc_key_id: Id,
    pub label: i64,
    pub encap: Vec<u8>,
}
/// AqcBidiChannelCreated policy effect.
#[effect]
pub struct AqcBidiChannelCreated {
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub author_enc_key_id: Id,
    pub peer_id: Id,
    pub peer_enc_pk: Vec<u8>,
    pub label: i64,
    pub channel_key_id: Id,
}
/// AqcBidiChannelReceived policy effect.
#[effect]
pub struct AqcBidiChannelReceived {
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub author_enc_pk: Vec<u8>,
    pub peer_id: Id,
    pub peer_enc_key_id: Id,
    pub label: i64,
    pub encap: Vec<u8>,
}
/// AqcUniChannelCreated policy effect.
#[effect]
pub struct AqcUniChannelCreated {
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub writer_id: Id,
    pub reader_id: Id,
    pub author_enc_key_id: Id,
    pub peer_enc_pk: Vec<u8>,
    pub label: i64,
    pub channel_key_id: Id,
}
/// AqcUniChannelReceived policy effect.
#[effect]
pub struct AqcUniChannelReceived {
    pub parent_cmd_id: Id,
    pub author_id: Id,
    pub writer_id: Id,
    pub reader_id: Id,
    pub author_enc_pk: Vec<u8>,
    pub peer_enc_key_id: Id,
    pub label: i64,
    pub encap: Vec<u8>,
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
/// QueryDeviceLabelAssignmentsResult policy effect.
#[effect]
pub struct QueryDeviceLabelAssignmentsResult {
    pub label: i64,
}
/// QueryAfcNetIdentifierResult policy effect.
#[effect]
pub struct QueryAfcNetIdentifierResult {
    pub net_identifier: String,
}
/// QueryAqcNetIdentifierResult policy effect.
#[effect]
pub struct QueryAqcNetIdentifierResult {
    pub net_identifier: String,
}
/// QueryLabelExistsResult policy effect.
#[effect]
pub struct QueryLabelExistsResult {
    pub label_exists: bool,
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
    fn define_label(&mut self, label: i64) -> Result<(), ClientError>;
    fn undefine_label(&mut self, label: i64) -> Result<(), ClientError>;
    fn assign_label(
        &mut self,
        device_id: Id,
        label: i64,
        op: ChanOp,
    ) -> Result<(), ClientError>;
    fn revoke_label(&mut self, device_id: Id, label: i64) -> Result<(), ClientError>;
    fn set_afc_network_name(
        &mut self,
        device_id: Id,
        net_identifier: String,
    ) -> Result<(), ClientError>;
    fn unset_afc_network_name(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn set_aqc_network_name(
        &mut self,
        device_id: Id,
        net_identifier: String,
    ) -> Result<(), ClientError>;
    fn unset_aqc_network_name(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn create_afc_bidi_channel(
        &mut self,
        peer_id: Id,
        label: i64,
    ) -> Result<(), ClientError>;
    fn create_afc_uni_channel(
        &mut self,
        writer_id: Id,
        reader_id: Id,
        label: i64,
    ) -> Result<(), ClientError>;
    fn create_aqc_bidi_channel(
        &mut self,
        peer_id: Id,
        label: i64,
    ) -> Result<(), ClientError>;
    fn create_aqc_uni_channel(
        &mut self,
        writer_id: Id,
        reader_id: Id,
        label: i64,
    ) -> Result<(), ClientError>;
    fn query_devices_on_team(&mut self) -> Result<(), ClientError>;
    fn query_device_role(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn query_device_keybundle(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn query_device_label_assignments(
        &mut self,
        device_id: Id,
    ) -> Result<(), ClientError>;
    fn query_afc_net_identifier(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn query_aqc_net_identifier(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn query_label_exists(&mut self, label: i64) -> Result<(), ClientError>;
}
