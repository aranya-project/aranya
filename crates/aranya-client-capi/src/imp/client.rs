use core::{mem::MaybeUninit, ops::Deref};

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::KeyBundle;

use crate::imp;

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
    keybundle: &KeyBundle,
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

/// Deserializes key bundle buffer into a [`KeyBundle`].
pub fn key_bundle_deserialize(buf: &[u8]) -> Result<KeyBundle, imp::Error> {
    Ok(postcard::from_bytes(buf)?)
}

/// An Aranya role.
#[derive(Debug)]
pub struct Role(aranya_client::Role);

impl Typed for Role {
    const TYPE_ID: TypeId = TypeId::new(0xA1B2C3D4);
}

impl Deref for Role {
    type Target = aranya_client::Role;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
