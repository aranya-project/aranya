use std::mem::MaybeUninit;

use aranya_capi_core::safe::{TypeId, Typed};

/// An instance of an Aranya Client, along with an async runtime.
pub struct Client {
    pub(crate) inner: aranya_client::Client,
    pub(crate) rt: tokio::runtime::Runtime,
}

impl Client {
    /// Useful for deref coercion.
    pub(crate) fn imp(&self) -> &Self {
        self
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
