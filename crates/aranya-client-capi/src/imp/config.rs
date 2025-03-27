use std::ffi::c_char;

use aranya_capi_core::safe::{TypeId, Typed};
use buggy::bug;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 32, align = 8)]
/// Configuration info for Aranya
pub struct ClientConfig {
    pub daemon_addr: *const c_char,
    #[cfg(feature = "afc")]
    pub afc: AfcConfig,
}

impl Typed for ClientConfig {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9E);
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg(feature = "afc")]
#[aranya_capi_core::opaque(size = 24, align = 8)]
/// Configuration info for Aranya Fast Channels
pub struct AfcConfig {
    /// Shared memory path.
    pub shm_path: *const c_char,
    /// Maximum number of channels to store in shared-memory.
    pub max_channels: usize,
    /// Address to bind AFC server to.
    pub addr: *const c_char,
}

#[cfg(feature = "afc")]
impl Typed for AfcConfig {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9F);
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 40, align = 8)]
/// Builder for a [`ClientConfig`]
pub struct ClientConfigBuilder {
    pub daemon_addr: *const c_char,
    #[cfg(feature = "afc")]
    pub afc: Option<AfcConfig>,
}

impl ClientConfigBuilder {
    /// Attempts to construct a [`ClientConfig`], returning an [`Error::Bug`](super::Error::Bug) if
    /// there are invalid parameters.
    pub fn build(self) -> Result<ClientConfig, super::Error> {
        if self.daemon_addr.is_null() {
            bug!("Tried to create a ClientConfig without a valid address!");
        }

        #[cfg(feature = "afc")]
        let Some(afc) = self.afc
        else {
            bug!("Tried to create a ClientConfig without a valid AfcConfig!");
        };

        Ok(ClientConfig {
            daemon_addr: self.daemon_addr,
            #[cfg(feature = "afc")]
            afc,
        })
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg(feature = "afc")]
#[aranya_capi_core::opaque(size = 24, align = 8)]
/// Builder for an [`AfcConfig`]
pub struct AfcConfigBuilder {
    /// Shared memory path.
    pub shm_path: *const c_char,
    /// Maximum number of channels to store in shared-memory.
    pub max_channels: usize,
    /// Address to bind AFC server to.
    pub addr: *const c_char,
}

#[cfg(feature = "afc")]
impl AfcConfigBuilder {
    /// Attempts to construct an [`AfcConfig`], returning an [`Error::Bug`](super::Error::Bug) if
    /// there are invalid parameters.
    pub fn build(self) -> Result<AfcConfig, super::Error> {
        if self.shm_path.is_null() {
            bug!("Tried to create an AfcConfig without a valid shm_path!");
        }

        if self.addr.is_null() {
            bug!("Tried to create an AfcConfig without a valid address!");
        }

        Ok(AfcConfig {
            shm_path: self.shm_path,
            max_channels: self.max_channels,
            addr: self.addr,
        })
    }
}
