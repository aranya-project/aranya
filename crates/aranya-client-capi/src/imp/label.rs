use std::{ffi::CString, mem::MaybeUninit};

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::LabelId;
use buggy::BugExt;

/// A label that can be assigned to a device.
pub struct Label {
    pub(crate) id: LabelId,
    pub(crate) name: CString,
    _pad: MaybeUninit<[u8; 2 * (8 - size_of::<usize>())]>,
}

impl Typed for Label {
    const TYPE_ID: TypeId = TypeId::new(0xbfafb41c);
}

impl TryFrom<aranya_client::Label> for Label {
    type Error = crate::imp::Error;

    fn try_from(value: aranya_client::Label) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            name: CString::new(value.name).assume("should not have null byte")?,
            _pad: MaybeUninit::uninit(),
        })
    }
}
