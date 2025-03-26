use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::afc;

pub struct Client {
    pub inner: aranya_client::Client,
    pub rt: tokio::runtime::Runtime,
    /// Cached message in case the buffer provided to `recv_msg`
    /// is too small.
    pub msg: Option<afc::Message>,
}

impl Typed for Client {
    const TYPE_ID: TypeId = TypeId::new(0xbbafb41c);
}

pub struct Devices {
    pub inner: aranya_client::Devices,
}

impl Typed for Devices {
    const TYPE_ID: TypeId = TypeId::new(0xbbafb41d);
}

pub struct Labels {
    pub inner: aranya_client::Labels,
}

impl Typed for Labels {
    const TYPE_ID: TypeId = TypeId::new(0xbbafb41e);
}
