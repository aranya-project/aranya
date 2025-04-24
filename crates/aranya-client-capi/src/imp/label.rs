use std::{
    ffi::{c_char, CString},
    mem::MaybeUninit,
};

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_daemon_api::LabelId;

/// A label that can be assigned to a device.
pub struct Label {
    id: LabelId,
    name: CString,
    _pad: MaybeUninit<[u8; 2 * (8 - size_of::<usize>())]>,
}

impl Typed for Label {
    const TYPE_ID: TypeId = TypeId::new(0xbfafb41c);
}

impl Label {
    pub fn set_id(&mut self, label_id: LabelId) {
        self.id = label_id;
    }

    pub fn get_id(&self) -> LabelId {
        self.id
    }

    pub fn set_name(&mut self, name: String) {
        self.name = CString::new(name).expect("expected to create string");
    }

    pub fn get_name(&self) -> *const c_char {
        self.name.as_ptr()
    }
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
