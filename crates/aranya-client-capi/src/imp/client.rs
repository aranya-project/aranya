use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::AfcMsg;

pub struct Client {
    pub inner: aranya_client::Client,
    pub rt: tokio::runtime::Runtime,
    pub msg: Option<AfcMsg>,
}

impl Typed for Client {
    const TYPE_ID: TypeId = TypeId::new(0xbbafb41c);
}
