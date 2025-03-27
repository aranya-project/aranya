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
    NetworkNameSet(NetworkNameSet),
    NetworkNameUnset(NetworkNameUnset),
    AfcBidiChannelCreated(AfcBidiChannelCreated),
    AfcBidiChannelReceived(AfcBidiChannelReceived),
    AfcUniChannelCreated(AfcUniChannelCreated),
    AfcUniChannelReceived(AfcUniChannelReceived),
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
    pub author_id: Id,
    pub label: String,
    pub label_id: i64,
}
/// LabelUndefined policy effect.
#[effect]
pub struct LabelUndefined {
    pub author_id: Id,
    pub label: String,
    pub label_id: i64,
}
/// LabelAssigned policy effect.
#[effect]
pub struct LabelAssigned {
    pub device_id: Id,
    pub label: String,
    pub op: ChanOp,
}
/// LabelRevoked policy effect.
#[effect]
pub struct LabelRevoked {
    pub device_id: Id,
    pub label: String,
}
/// NetworkNameSet policy effect.
#[effect]
pub struct NetworkNameSet {
    pub device_id: Id,
    pub net_identifier: String,
}
/// NetworkNameUnset policy effect.
#[effect]
pub struct NetworkNameUnset {
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
    pub label: String,
    pub label_id: i64,
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
    pub label: String,
    pub label_id: i64,
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
    pub label: String,
    pub label_id: i64,
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
    pub label: String,
    pub label_id: i64,
    pub encap: Vec<u8>,
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
    fn define_label(&mut self, label: String) -> Result<(), ClientError>;
    fn undefine_label(&mut self, label: String) -> Result<(), ClientError>;
    fn assign_label(
        &mut self,
        device_id: Id,
        label: String,
        op: ChanOp,
    ) -> Result<(), ClientError>;
    fn revoke_label(&mut self, device_id: Id, label: String) -> Result<(), ClientError>;
    fn set_network_name(
        &mut self,
        device_id: Id,
        net_identifier: String,
    ) -> Result<(), ClientError>;
    fn unset_network_name(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn create_afc_bidi_channel(
        &mut self,
        peer_id: Id,
        label: String,
    ) -> Result<(), ClientError>;
    fn create_afc_uni_channel(
        &mut self,
        writer_id: Id,
        reader_id: Id,
        label: String,
    ) -> Result<(), ClientError>;
}
