use std::{ffi::CString, mem::MaybeUninit};

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_daemon_api::RoleId;

/// A role on the team.
pub struct Role {
    pub(crate) id: RoleId,
    pub(crate) name: CString,
    _pad: MaybeUninit<[u8; 2 * (8 - size_of::<usize>())]>,
}

impl Typed for Role {
    const TYPE_ID: TypeId = TypeId::new(0xbcafb41c);
}

impl From<aranya_daemon_api::Role> for Role {
    fn from(value: aranya_daemon_api::Role) -> Self {
        Self {
            id: value.id,
            name: CString::new(value.name).expect("expected to create string"),
            _pad: MaybeUninit::uninit(),
        }
    }
}
