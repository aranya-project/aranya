use std::{ffi::CString, mem::MaybeUninit};

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_daemon_api::LabelId;

/// A label that can be assigned to a device.
pub struct Label {
    pub(crate) id: LabelId,
    pub(crate) name: CString,
    _pad: MaybeUninit<[u8; 2 * (8 - size_of::<usize>())]>,
}

impl Typed for Label {
    const TYPE_ID: TypeId = TypeId::new(0xbfafb41c);
}

impl From<aranya_daemon_api::Label> for Label {
    fn from(value: aranya_daemon_api::Label) -> Self {
        Self {
            id: value.id,
            name: CString::new(value.name).expect("expected to create string"),
            _pad: MaybeUninit::uninit(),
        }
    }
}
