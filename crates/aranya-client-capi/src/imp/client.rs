use core::mem::MaybeUninit;

use aranya_client::PubKeyBundle;

use crate::imp;

/// An instance of an Aranya Client, along with an async runtime.
#[derive(Debug)]
pub struct Client {
    pub(crate) inner: aranya_client::Client,
    pub(crate) rt: tokio::runtime::Runtime,
}

/// Serializes a [`PubKeyBundle`] into the output buffer.
pub unsafe fn key_bundle_serialize(
    keybundle: &PubKeyBundle,
    buf: *mut MaybeUninit<u8>,
    buf_len: &mut usize,
) -> Result<(), imp::Error> {
    let data = postcard::to_allocvec(&keybundle)?;

    if *buf_len < data.len() {
        *buf_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    }
    // SAFETY: Must trust caller provides valid ptr/len.
    let out = aranya_capi_core::try_as_mut_slice!(buf, *buf_len);
    for (dst, src) in out.iter_mut().zip(&data) {
        dst.write(*src);
    }
    *buf_len = data.len();

    Ok(())
}

/// Deserializes key bundle buffer into a [`PubKeyBundle`].
pub fn key_bundle_deserialize(buf: &[u8]) -> Result<PubKeyBundle, imp::Error> {
    Ok(postcard::from_bytes(buf)?)
}
