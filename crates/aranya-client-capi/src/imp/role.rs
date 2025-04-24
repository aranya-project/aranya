use std::{
    ffi::{c_char, CString},
    mem::MaybeUninit,
};

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_daemon_api::RoleId;

/// A role on the team.
pub struct Role {
    id: RoleId,
    name: CString,
    _pad: MaybeUninit<[u8; 2 * (8 - size_of::<usize>())]>,
}

impl Typed for Role {
    const TYPE_ID: TypeId = TypeId::new(0xbcafb41c);
}

impl Role {
    pub fn set_id(&mut self, role_id: RoleId) {
        self.id = role_id;
    }

    pub fn get_id(&self) -> RoleId {
        self.id
    }

    pub fn set_name(&mut self, name: String) {
        self.name = CString::new(name).expect("expected to create string");
    }

    pub fn get_name(&self) -> *const c_char {
        self.name.as_ptr()
    }
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
