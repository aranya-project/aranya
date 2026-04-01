use core::mem::MaybeUninit;
use std::{ffi::CString, str::FromStr};

use aranya_client::{PublicKeyBundle, Text};

use crate::imp;

/// An instance of an Aranya Client, along with an async runtime.
#[derive(Debug)]
pub struct Client {
    pub(crate) inner: aranya_client::Client,
    pub(crate) rt: tokio::runtime::Runtime,
}

/// Serializes a [`PublicKeyBundle`] into the output buffer.
pub unsafe fn public_key_bundle_serialize(
    public_key_bundle: &PublicKeyBundle,
    buf: *mut MaybeUninit<u8>,
    buf_len: &mut usize,
) -> Result<(), imp::Error> {
    let data = postcard::to_allocvec(&public_key_bundle)?;

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

/// Deserializes key bundle buffer into a [`PublicKeyBundle`].
pub fn public_key_bundle_deserialize(buf: &[u8]) -> Result<PublicKeyBundle, imp::Error> {
    Ok(postcard::from_bytes(buf)?)
}

#[derive(Debug)]
pub struct Role {
    pub id: aranya_client::RoleId,
    pub name: CString,
    pub author_id: aranya_client::DeviceId,
    pub default: bool,
}

impl From<aranya_client::Role> for Role {
    fn from(role: aranya_client::Role) -> Self {
        let name = CString::from_str(Text::as_str(&role.name)).expect("text cannot contain nul");
        Self {
            id: role.id,
            name,
            author_id: role.author_id,
            default: role.default,
        }
    }
}
