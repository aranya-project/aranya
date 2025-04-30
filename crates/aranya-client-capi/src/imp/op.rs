use aranya_capi_core::safe::{TypeId, Typed};

/// An operation that a role can perform.
#[derive(Copy, Clone, Debug)]
pub struct Op {
    pub(crate) op: crate::api::defs::Op,
}

impl Typed for Op {
    const TYPE_ID: TypeId = TypeId::new(0xbfafe41c);
}

impl Op {
    pub(crate) fn new(op: crate::api::defs::Op) -> Self {
        Self { op }
    }
}
