use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::afc::Message;

pub struct Client {
    pub inner: aranya_client::Client,
    pub rt: tokio::runtime::Runtime,
    /// Cached message in case the buffer provided to `recv_msg`
    /// is too small.
    pub msg: Option<Message>,
}

impl Typed for Client {
    const TYPE_ID: TypeId = TypeId::new(0xbbafb41c);
}
