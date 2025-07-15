//! Client-daemon connection.

mod client;
mod device;
mod label;
mod net_id;
mod role;
mod team;

#[doc(inline)]
pub use crate::client::{
    client::{Client, ClientBuilder, KeyBundle},
    device::{Device, DeviceId, Devices},
    label::{ChanOp, Label, LabelId, Labels},
    net_id::{InvalidNetIdentifier, NetIdentifier},
    role::{Role, RoleId, Roles},
    team::{Team, TeamId},
};
