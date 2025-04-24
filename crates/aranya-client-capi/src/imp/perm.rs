use std::{
    ffi::{c_char, CString},
    fmt,
};

use aranya_capi_core::safe::{TypeId, Typed};

/// A permission that can be assigned to a role.
#[derive(Clone, Debug)]
pub struct Perm {
    name: CString,
}

impl Typed for Perm {
    const TYPE_ID: TypeId = TypeId::new(0xecafb41c);
}

impl Perm {
    pub fn set_name(&mut self, name: String) {
        self.name = CString::new(name).expect("expected to create string");
    }

    pub fn get_name(&self) -> *const c_char {
        self.name.as_ptr()
    }
}

impl From<aranya_daemon_api::Permission> for Perm {
    fn from(value: aranya_daemon_api::Permission) -> Self {
        Self {
            name: CString::new(value).expect("expected to create string"),
        }
    }
}

impl From<Perm> for String {
    fn from(value: Perm) -> Self {
        value
            .name
            .into_string()
            .expect("expected to convert to string")
    }
}

impl fmt::Display for Perm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.name.clone().into_string().expect("expected to convert to string")
        )
    }
}
