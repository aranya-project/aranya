use std::{mem::MaybeUninit, sync::Arc};

use aranya_capi_core::safe::{TypeId, Typed};
use tokio::sync::Mutex;

/// An instance of an Aranya Client, along with an async runtime.
pub struct Client {
    pub(crate) inner: Arc<Mutex<aranya_client::Client>>,
    pub(crate) rt: Arc<Mutex<tokio::runtime::Runtime>>,
}

impl Client {
    /// Useful for deref coercion.
    pub(crate) fn imp(&self) -> &Self {
        self
    }

    /// Get ARC references to client and runtime.
    pub(crate) fn get_arcs(
        &self,
    ) -> (
        Arc<Mutex<aranya_client::Client>>,
        Arc<Mutex<tokio::runtime::Runtime>>,
    ) {
        (self.inner.clone(), self.rt.clone())
    }
}

impl Client {
    pub(crate) fn new(client: aranya_client::Client, rt: tokio::runtime::Runtime) -> Self {
        Self {
            inner: Arc::new(Mutex::new(client)),
            rt: Arc::new(Mutex::new(rt)),
        }
    }
}

impl Typed for Client {
    const TYPE_ID: TypeId = TypeId::new(0xBBAFB41C);
}

/// Serializes a [`KeyBundle`] into the output buffer.
pub unsafe fn key_bundle_serialize(
    keybundle: &aranya_daemon_api::KeyBundle,
    buf: *mut MaybeUninit<u8>,
    buf_len: &mut usize,
) -> Result<(), crate::imp::Error> {
    let data = postcard::to_allocvec(&keybundle)?;

    if *buf_len < data.len() {
        *buf_len = data.len();
        return Err(crate::imp::Error::BufferTooSmall);
    }
    // SAFETY: Must trust caller provides valid ptr/len.
    let out = aranya_capi_core::try_as_mut_slice!(buf, *buf_len);
    for (dst, src) in out.iter_mut().zip(&data) {
        dst.write(*src);
    }
    *buf_len = data.len();

    Ok(())
}

/// Deserializes key bundle buffer into a [`KeyBundle`].
pub fn key_bundle_deserialize(
    buf: &[u8],
) -> Result<aranya_daemon_api::KeyBundle, crate::imp::Error> {
    Ok(postcard::from_bytes(buf)?)
}
