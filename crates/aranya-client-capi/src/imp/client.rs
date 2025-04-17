use std::mem::MaybeUninit;

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

/// Serializes the KeyBundle and writes the bytes to the output buffer.
///
/// The buffer must have enough memory allocated to it to store the serialized KeyBundle.
/// The exact size depends on the the underlying cipher-suite.
/// Starting with a buffer size of 256 bytes will work for the default cipher-suite.
///
/// If the buffer does not have enough space, a `::ARANYA_ERROR_BUFFER_TOO_SMALL` error will be returned.
/// This gives the caller the opportunity to allocate a larger buffer and try again.
///
/// @param keybundle KeyBundle [`KeyBundle`].
/// @param buf keybundle byte buffer [`KeyBundle`].
/// @param buf_len returns the length of the serialized keybundle.
///
/// @relates KeyBundle.
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

/// Converts serialized bytes into a key bundle.
///
/// The KeyBundle buffer is expected to have been serialized with `aranya_key_bundle_serialize()`.
/// The buffer pointer and length must correspond to a valid buffer allocated by the caller.
///
/// @param buf serialized keybundle byte buffer [`KeyBundle`].
/// @param buf_len is the length of the serialized keybundle.
///
/// Output params:
/// @param keybundle KeyBundle [`KeyBundle`].
///
/// @relates KeyBundle.
pub fn key_bundle_deserialize(
    buf: &[u8],
) -> Result<aranya_daemon_api::KeyBundle, crate::imp::Error> {
    Ok(postcard::from_bytes(buf)?)
}
