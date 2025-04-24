use std::{
    ffi::{c_char, CString},
    fmt,
    mem::MaybeUninit,
};

use aranya_capi_core::safe::{TypeId, Typed};

/// A command that can be assigned to a role.
#[derive(Clone, Debug)]
pub struct Cmd {
    name: CString,
    _pad: MaybeUninit<[u8; 2 * (8 - size_of::<usize>())]>,
}

impl Typed for Cmd {
    const TYPE_ID: TypeId = TypeId::new(0xecafb41c);
}

impl Cmd {
    pub fn set_name(&mut self, name: String) {
        self.name = CString::new(name).expect("expected to create string");
    }

    pub fn get_name(&self) -> *const c_char {
        self.name.as_ptr()
    }
}

impl From<aranya_daemon_api::Cmd> for Cmd {
    fn from(value: aranya_daemon_api::Cmd) -> Self {
        Self {
            name: CString::new(value).expect("expected to create string"),
            _pad: MaybeUninit::uninit(),
        }
    }
}

impl From<Cmd> for String {
    fn from(value: Cmd) -> Self {
        value
            .name
            .into_string()
            .expect("expected to convert to string")
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.name
                .clone()
                .into_string()
                .expect("expected to convert to string")
        )
    }
}
