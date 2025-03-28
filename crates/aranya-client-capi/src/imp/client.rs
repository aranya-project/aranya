use aranya_capi_core::safe::{TypeId, Typed};
#[cfg(feature = "afc")]
use aranya_client::afc;

pub struct Client {
    pub inner: aranya_client::Client,
    pub rt: tokio::runtime::Runtime,
    /// Cached message in case the buffer provided to `recv_msg`
    /// is too small.
    #[cfg(feature = "afc")]
    pub msg: Option<afc::Message>,
}

impl Typed for Client {
    const TYPE_ID: TypeId = TypeId::new(0xbbafb41c);
}
