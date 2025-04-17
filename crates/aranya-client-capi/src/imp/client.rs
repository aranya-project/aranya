use std::mem::MaybeUninit;

use aranya_capi_core::safe::{TypeId, Typed};
#[cfg(feature = "afc")]
use aranya_client::afc;

pub struct Client {
    pub(crate) inner: aranya_client::Client,
    pub(crate) rt: tokio::runtime::Runtime,
    /// Cached message in case the buffer provided to `recv_msg`
    /// is too small.
    #[cfg(feature = "afc")]
    pub msg: Option<afc::Message>,
}

impl Typed for Client {
    const TYPE_ID: TypeId = TypeId::new(0xbbafb41c);
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
