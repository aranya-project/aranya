use std::{ffi::CString, mem::MaybeUninit};

use aranya_capi_core::safe::{TypeId, Typed};

/// A command that can be assigned to a role.
#[derive(Clone, Debug)]
pub struct Cmd {
    pub(crate) name: CString,
    _pad: MaybeUninit<[u8; 2 * (8 - size_of::<usize>())]>,
}

impl Typed for Cmd {
    const TYPE_ID: TypeId = TypeId::new(0xecafb41c);
}

impl TryFrom<aranya_daemon_api::Cmd> for Cmd {
    type Error = crate::imp::Error;

    fn try_from(value: aranya_daemon_api::Cmd) -> Result<Self, Self::Error> {
        Ok(Self {
            name: CString::new(value).map_err(crate::imp::Error::CString)?,
            _pad: MaybeUninit::uninit(),
        })
    }
}
