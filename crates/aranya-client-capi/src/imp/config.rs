use std::ffi::c_char;

use aranya_capi_core::safe::{TypeId, Typed};
use buggy::bug;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 32, align = 8)]
/// Configuration info for Aranya
pub struct ClientConfig {
    pub daemon_addr: *const c_char,
    #[cfg(feature = "experimental")]
    pub afc: AfcConfig,
}

impl Typed for ClientConfig {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9E);
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg(feature = "experimental")]
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

#[cfg(feature = "experimental")]
impl Typed for AfcConfig {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9F);
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 40, align = 8)]
/// Builder for a [`ClientConfig`]
pub struct ClientConfigBuilder {
    daemon_addr: *const c_char,
    #[cfg(feature = "experimental")]
    afc: Option<AfcConfig>,
}

impl ClientConfigBuilder {
    /// Creates a new [`ClientConfigBuilder`]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the daemon address that the Client should try to connect to.
    pub fn with_daemon_addr(mut self, address: *const c_char) -> Self {
        self.daemon_addr = address;
        self
    }

    #[cfg(feature = "experimental")]
    /// Sets the configuration for Aranya Fast Channels.
    pub fn with_afc_config(mut self, afc: AfcConfig) -> Self {
        self.afc = Some(afc);
        self
    }

    /// Attempts to construct a [`ClientConfig`], returning an [`Error::Bug`](super::Error::Bug) if
    /// there are invalid parameters.
    pub fn build(self) -> Result<ClientConfig, super::Error> {
        if self.daemon_addr.is_null() {
            bug!("Tried to create a ClientConfig without a valid address!");
        }

        #[cfg(feature = "experimental")]
        let Some(afc) = self.afc
        else {
            bug!("Tried to create a ClientConfig without a valid AfcConfig!");
        };

        Ok(ClientConfig {
            daemon_addr: self.daemon_addr,
            #[cfg(feature = "experimental")]
            afc,
        })
    }
}

impl Typed for ClientConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x227DFCA0);
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self {
            daemon_addr: std::ptr::null(),
            #[cfg(feature = "experimental")]
            afc: None,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg(feature = "experimental")]
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

#[cfg(feature = "experimental")]
impl AfcConfigBuilder {
    /// Creates a new [`AfcConfigBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the shared memory path that AFC should use for storing channel data.
    pub fn with_shm_path(mut self, shm_path: *const c_char) -> Self {
        self.shm_path = shm_path;
        self
    }

    /// Sets the maximum number of channels that are stored in shared memory.
    pub fn with_max_channels(mut self, channels: usize) -> Self {
        self.max_channels = channels;
        self
    }

    /// Sets the address that the AFC server should bind to for listening.
    pub fn with_address(mut self, address: *const c_char) -> Self {
        self.addr = address;
        self
    }

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

#[cfg(feature = "experimental")]
impl Typed for AfcConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x227DFCA1);
}

#[cfg(feature = "experimental")]
impl Default for AfcConfigBuilder {
    fn default() -> Self {
        Self {
            shm_path: std::ptr::null(),
            max_channels: 0,
            addr: std::ptr::null(),
        }
    }
}
