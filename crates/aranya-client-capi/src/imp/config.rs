//! Client configuration for C API.

use core::{ffi::c_char, mem::MaybeUninit, ptr};

use aranya_capi_core::{Builder, InvalidArg};

use super::Error;
use crate::api::defs::{self, Duration};

/// Configuration info for Aranya
#[derive(Clone, Debug)]
pub struct ClientConfig {
    daemon_addr: *const c_char,
}

impl ClientConfig {
    pub(crate) fn daemon_addr(&self) -> *const c_char {
        self.daemon_addr
    }
}

/// Builder for a [`ClientConfig`]
#[derive(Clone, Debug)]
pub struct ClientConfigBuilder {
    daemon_addr: *const c_char,
}

impl ClientConfigBuilder {
    /// Set the address for the daemon
    pub fn daemon_addr(&mut self, addr: *const c_char) {
        self.daemon_addr = addr;
    }
}

impl Builder for ClientConfigBuilder {
    type Output = defs::ClientConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        if self.daemon_addr.is_null() {
            return Err(InvalidArg::new("daemon_addr", "field not set").into());
        }

        let cfg = ClientConfig {
            daemon_addr: self.daemon_addr,
        };
        Self::Output::init(out, cfg);
        Ok(())
    }
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self {
            daemon_addr: ptr::null(),
        }
    }
}

/// Configuration values for syncing with a peer
#[derive(Clone, Debug)]
pub struct SyncPeerConfig {
    interval: Option<Duration>,
    sync_now: bool,
    #[cfg(feature = "preview")]
    sync_on_hello: bool,
}

impl From<SyncPeerConfig> for aranya_client::SyncPeerConfig {
    fn from(value: SyncPeerConfig) -> Self {
        let mut builder = Self::builder();
        if let Some(interval) = value.interval {
            builder = builder.interval(interval.into());
        }
        builder = builder.sync_now(value.sync_now);
        #[cfg(feature = "preview")]
        {
            builder = builder.sync_on_hello(value.sync_on_hello);
        }
        builder.build().expect("All values are set")
    }
}

impl From<&SyncPeerConfig> for aranya_client::SyncPeerConfig {
    fn from(value: &SyncPeerConfig) -> Self {
        value.clone().into()
    }
}

/// Builder for a [`SyncPeerConfig`]
#[derive(Clone, Debug)]
pub struct SyncPeerConfigBuilder {
    interval: Option<Duration>,
    sync_now: bool,
    #[cfg(feature = "preview")]
    sync_on_hello: bool,
}

impl SyncPeerConfigBuilder {
    /// Set the interval at which syncing occurs
    pub fn interval(&mut self, duration: Duration) {
        self.interval = Some(duration);
    }

    /// Configures whether the peer will be scheduled for an immediate sync when added.
    ///
    /// By default, the peer is scheduled for an immediate sync.
    pub fn sync_now(&mut self, sync_now: bool) {
        self.sync_now = sync_now;
    }

    /// Configures whether to automatically sync when a hello message is received from this peer
    /// indicating they have a head that we don't have.
    ///
    /// By default, sync on hello is disabled.
    #[cfg(feature = "preview")]
    pub fn sync_on_hello(&mut self, sync_on_hello: bool) {
        self.sync_on_hello = sync_on_hello;
    }
}

impl Builder for SyncPeerConfigBuilder {
    type Output = defs::SyncPeerConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        let cfg = SyncPeerConfig {
            interval: self.interval,
            sync_now: self.sync_now,
            #[cfg(feature = "preview")]
            sync_on_hello: self.sync_on_hello,
        };
        Self::Output::init(out, cfg);
        Ok(())
    }
}

impl Default for SyncPeerConfigBuilder {
    fn default() -> Self {
        Self {
            interval: None,
            sync_now: true,
            #[cfg(feature = "preview")]
            sync_on_hello: false,
        }
    }
}

/// A team config required to create a new Aranya team.
///
/// This type exists for backward compatibility. With mTLS authentication,
/// team configuration is no longer required.
#[derive(Clone, Debug, Default)]
pub struct CreateTeamConfig {}

impl CreateTeamConfig {
    fn new() -> Self {
        Self {}
    }

    /// Creates a new [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        CreateTeamConfigBuilder::default()
    }
}

/// Builder for constructing a [`CreateTeamConfig`].
#[derive(Debug, Default)]
pub struct CreateTeamConfigBuilder {
    #[allow(dead_code)]
    quic_sync: Option<aranya_client::CreateTeamQuicSyncConfig>,
}

impl CreateTeamConfigBuilder {
    /// Sets the QUIC sync configuration (ignored - for backward compatibility).
    pub fn quic(&mut self, config: aranya_client::CreateTeamQuicSyncConfig) {
        self.quic_sync = Some(config);
    }
}

impl Builder for CreateTeamConfigBuilder {
    type Output = defs::CreateTeamConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        Self::Output::init(out, CreateTeamConfig::new());
        Ok(())
    }
}

impl From<CreateTeamConfig> for aranya_client::CreateTeamConfig {
    fn from(_value: CreateTeamConfig) -> Self {
        Self::builder().build().expect("All fields set")
    }
}

impl From<&CreateTeamConfig> for aranya_client::CreateTeamConfig {
    fn from(value: &CreateTeamConfig) -> Self {
        Self::from(value.clone())
    }
}

/// Configuration for adding an existing Aranya team to a device.
///
/// This type exists for backward compatibility. With mTLS authentication,
/// devices authenticate via certificates at the connection level.
#[derive(Clone, Debug)]
pub struct AddTeamConfig {
    team_id: defs::TeamId,
}

impl AddTeamConfig {
    fn new(team_id: defs::TeamId) -> Self {
        Self { team_id }
    }

    /// Creates a new [`AddTeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        AddTeamConfigBuilder::default()
    }
}

/// Builder for constructing an [`AddTeamConfig`].
#[derive(Debug, Default)]
pub struct AddTeamConfigBuilder {
    team_id: Option<defs::TeamId>,
    #[allow(dead_code)]
    quic_sync: Option<aranya_client::AddTeamQuicSyncConfig>,
}

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn id(&mut self, id: defs::TeamId) {
        self.team_id = Some(id);
    }

    /// Sets the QUIC sync configuration (ignored - for backward compatibility).
    pub fn quic(&mut self, config: aranya_client::AddTeamQuicSyncConfig) {
        self.quic_sync = Some(config);
    }
}

impl Builder for AddTeamConfigBuilder {
    type Output = defs::AddTeamConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        let Some(id) = self.team_id else {
            return Err(InvalidArg::new("id", "field not set").into());
        };

        Self::Output::init(out, AddTeamConfig::new(id));
        Ok(())
    }
}

impl From<AddTeamConfig> for aranya_client::AddTeamConfig {
    fn from(value: AddTeamConfig) -> Self {
        Self::builder()
            .team_id((&value.team_id).into())
            .build()
            .expect("All fields set")
    }
}

impl From<&AddTeamConfig> for aranya_client::AddTeamConfig {
    fn from(value: &AddTeamConfig) -> Self {
        Self::from(value.clone())
    }
}

// ============================================================================
// QuicSyncConfig types (backward compatibility - these are no-ops with mTLS)
// ============================================================================

/// QUIC syncer configuration for CreateTeam() operation.
///
/// This type exists for backward compatibility. With mTLS authentication,
/// PSK seeds are no longer used and this configuration is ignored.
#[derive(Clone, Debug, Default)]
pub struct CreateTeamQuicSyncConfig {
    mode: aranya_client::config::CreateSeedMode,
}

impl CreateTeamQuicSyncConfig {
    fn new(mode: aranya_client::config::CreateSeedMode) -> Self {
        Self { mode }
    }

    /// Creates a new [`CreateTeamQuicSyncConfigBuilder`].
    pub fn builder() -> CreateTeamQuicSyncConfigBuilder {
        CreateTeamQuicSyncConfigBuilder::default()
    }
}

/// Builder for constructing a [`CreateTeamQuicSyncConfig`].
#[derive(Debug, Default)]
pub struct CreateTeamQuicSyncConfigBuilder {
    mode: aranya_client::config::CreateSeedMode,
}

impl CreateTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode to generate.
    pub fn gen_seed(&mut self) {
        self.mode = aranya_client::config::CreateSeedMode::Generate;
    }

    /// Sets the PSK seed mode to IKM.
    pub fn seed_ikm(&mut self, ikm: [u8; aranya_client::config::SEED_IKM_SIZE]) {
        self.mode = aranya_client::config::CreateSeedMode::IKM(ikm);
    }
}

impl Builder for CreateTeamQuicSyncConfigBuilder {
    type Output = defs::CreateTeamQuicSyncConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        Self::Output::init(out, CreateTeamQuicSyncConfig::new(self.mode));
        Ok(())
    }
}

impl From<CreateTeamQuicSyncConfig> for aranya_client::CreateTeamQuicSyncConfig {
    fn from(value: CreateTeamQuicSyncConfig) -> Self {
        Self::builder().mode(value.mode).build().expect("valid")
    }
}

impl From<&CreateTeamQuicSyncConfig> for aranya_client::CreateTeamQuicSyncConfig {
    fn from(value: &CreateTeamQuicSyncConfig) -> Self {
        Self::from(value.clone())
    }
}

/// QUIC syncer configuration for AddTeam() operation.
///
/// This type exists for backward compatibility. With mTLS authentication,
/// PSK seeds are no longer used and this configuration is ignored.
#[derive(Clone, Debug)]
pub struct AddTeamQuicSyncConfig {
    mode: aranya_client::config::AddSeedMode,
}

impl AddTeamQuicSyncConfig {
    fn new(mode: aranya_client::config::AddSeedMode) -> Self {
        Self { mode }
    }

    /// Creates a new [`AddTeamQuicSyncConfigBuilder`].
    pub fn builder() -> AddTeamQuicSyncConfigBuilder {
        AddTeamQuicSyncConfigBuilder::default()
    }
}

/// Builder for constructing an [`AddTeamQuicSyncConfig`].
#[derive(Debug, Default)]
pub struct AddTeamQuicSyncConfigBuilder {
    mode: Option<aranya_client::config::AddSeedMode>,
}

impl AddTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode to IKM.
    pub fn seed_ikm(&mut self, ikm: [u8; aranya_client::config::SEED_IKM_SIZE]) {
        self.mode = Some(aranya_client::config::AddSeedMode::IKM(ikm));
    }

    /// Sets the PSK seed mode to wrapped.
    pub fn wrapped_seed(&mut self, wrapped_seed: &[u8]) {
        self.mode = Some(aranya_client::config::AddSeedMode::Wrapped(
            wrapped_seed.to_vec(),
        ));
    }
}

impl Builder for AddTeamQuicSyncConfigBuilder {
    type Output = defs::AddTeamQuicSyncConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        let Some(mode) = self.mode else {
            return Err(InvalidArg::new("mode", "field not set").into());
        };

        Self::Output::init(out, AddTeamQuicSyncConfig::new(mode));
        Ok(())
    }
}

impl From<AddTeamQuicSyncConfig> for aranya_client::AddTeamQuicSyncConfig {
    fn from(value: AddTeamQuicSyncConfig) -> Self {
        Self::builder().mode(value.mode).build().expect("valid")
    }
}

impl From<&AddTeamQuicSyncConfig> for aranya_client::AddTeamQuicSyncConfig {
    fn from(value: &AddTeamQuicSyncConfig) -> Self {
        Self::from(value.clone())
    }
}
