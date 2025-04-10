#[cfg(feature = "afc")]
use core::ptr;
use core::{ffi::c_char, ops::DerefMut, slice};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use aranya_capi_core::{prelude::*, ErrorCode, InvalidArg};
use tracing::debug;

use crate::imp;

/// An error code.
///
/// For extended error information, see [`ExtError`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, ErrorCode)]
#[repr(u32)]
pub enum Error {
    /// Success.
    #[capi(success)]
    #[capi(msg = "success")]
    Success,

    /// Internal bug discovered.
    #[capi(msg = "internal bug discovered")]
    Bug,

    /// Timed out.
    #[capi(msg = "timed out")]
    Timeout,

    /// Logging initialization failure.
    #[capi(msg = "logging initialization failure")]
    LogInit,

    /// Invalid argument.
    #[capi(msg = "invalid argument")]
    InvalidArgument,

    /// Buffer is too small.
    #[capi(msg = "buffer too small")]
    BufferTooSmall,

    /// Invalid UTF-8.
    #[capi(msg = "invalid utf8")]
    InvalidUtf8,

    /// Invalid Address.
    #[capi(msg = "invalid address")]
    InvalidAddr,

    /// Error connecting to daemon.
    #[capi(msg = "could not connect to daemon")]
    Connecting,

    /// Could not send request to daemon.
    #[capi(msg = "could not send request to daemon")]
    Rpc,

    /// Daemon reported error.
    #[capi(msg = "daemon reported error")]
    Daemon,

    /// AFC library error.
    #[capi(msg = "AFC library error")]
    Afc,

    #[capi(msg = "tokio runtime error")]
    Runtime,

    #[capi(msg = "invalid index")]
    InvalidIndex,
}

impl From<&imp::Error> for Error {
    fn from(err: &imp::Error) -> Self {
        debug!(?err);
        match err {
            imp::Error::Bug(_) => Self::Bug,
            imp::Error::Timeout(_) => Self::Timeout,
            imp::Error::LogInit(_) => Self::LogInit,
            imp::Error::InvalidArg(_) => Self::InvalidArgument,
            imp::Error::Utf8(_) => Self::InvalidUtf8,
            imp::Error::Addr(_) => Self::InvalidAddr,
            imp::Error::BufferTooSmall => Self::BufferTooSmall,
            imp::Error::Client(err) => match err {
                aranya_client::Error::Connecting(_) => Self::Connecting,
                aranya_client::Error::Rpc(_) => Self::Rpc,
                aranya_client::Error::Daemon(_) => Self::Daemon,
                #[cfg(feature = "afc")]
                aranya_client::Error::Afc(_) => Self::Afc,
                aranya_client::Error::Bug(_) => Self::Bug,
                aranya_client::Error::InvalidArg { .. } => Self::InvalidArgument,
            },
            imp::Error::Runtime(_) => Self::Runtime,
            imp::Error::InvalidIndex(_) => Self::InvalidIndex,
        }
    }
}

impl From<InvalidArg<'static>> for Error {
    fn from(_err: InvalidArg<'static>) -> Self {
        Self::InvalidArgument
    }
}

impl From<&InvalidArg<'static>> for Error {
    fn from(_err: &InvalidArg<'static>) -> Self {
        Self::InvalidArgument
    }
}

/// Returns a human-readable error message for an [`Error`].
///
/// The resulting pointer must NOT be freed.
///
/// @param err `u32` error code from `AranyaError`.
///
/// @relates AranyaError.
#[aranya_capi_core::no_ext_error]
pub fn error_to_str(err: u32) -> *const c_char {
    match Error::try_from_repr(err) {
        Some(v) => v.to_cstr().as_ptr(),
        None => c"invalid error code".as_ptr(),
    }
}

/// Extended error information.
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 80, align = 8)]
pub type ExtError = Safe<imp::ExtError>;

/// Copies the extended error's message into `msg`.
///
/// If `msg_len` is large enough to fit the entire message,
/// including the trailing null byte, it updates `msg_len`
/// with the length of the message and copies the message
/// into `msg`.
///
/// Otherwise, if `msg_len` is not large enough to fit the
/// entire message, including the trailing null byte, it
/// updates `msg_len` with the length of the message and
/// returns `::ARANYA_ERROR_BUFFER_TOO_SMALL`.
///
/// @param err the error to get a message for [`ExtError`].
/// @param msg buffer to copy error message into.
/// @param msg_len length of the message buffer.
///
/// @relates AranyaExtError.
pub fn ext_error_msg(
    err: &ExtError,
    msg: &mut MaybeUninit<c_char>,
    msg_len: &mut usize,
) -> Result<(), imp::Error> {
    let msg = aranya_capi_core::try_as_mut_slice!(msg, *msg_len);
    err.copy_msg(msg, msg_len)
}

/// Initializes logging.
///
/// Assumes the `ARANYA_CAPI` environment variable has been set to the desired tracing log level.
/// E.g. `ARANYA_CAPI=debug`.
pub fn init_logging() -> Result<(), imp::Error> {
    use tracing_subscriber::{prelude::*, EnvFilter};
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_env("ARANYA_CAPI"))
        .try_init()?;
    Ok(())
}

/// A handle to an Aranya Client.
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 2656, align = 16)]
pub type Client = Safe<imp::Client>;

/// The size in bytes of an ID
pub const ARANYA_ID_LEN: usize = 64;

const _: () = {
    assert!(ARANYA_ID_LEN == size_of::<aranya_crypto::Id>());
};

// Aranya ID
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Id {
    bytes: [u8; ARANYA_ID_LEN],
}

impl From<&Id> for aranya_crypto::Id {
    fn from(value: &Id) -> Self {
        Self::from(value.bytes)
    }
}

/// Team ID.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TeamId {
    id: Id,
}

impl From<aranya_daemon_api::TeamId> for TeamId {
    fn from(value: aranya_daemon_api::TeamId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&TeamId> for aranya_daemon_api::TeamId {
    fn from(value: &TeamId) -> Self {
        value.id.bytes.into()
    }
}

/// Device ID.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DeviceId {
    id: Id,
}

impl From<aranya_daemon_api::DeviceId> for DeviceId {
    fn from(value: aranya_daemon_api::DeviceId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&DeviceId> for aranya_daemon_api::DeviceId {
    fn from(value: &DeviceId) -> Self {
        value.id.bytes.into()
    }
}

/// Channel ID for a fast channel.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 16, align = 1)]
#[cfg(feature = "afc")]
pub struct ChannelId(aranya_daemon_api::AfcId);

/// An enum containing team roles defined in the Aranya policy.
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum Role {
    /// Owner role.
    Owner,
    /// Admin role.
    Admin,
    /// Operator role.
    Operator,
    /// Member role.
    Member,
}

impl From<Role> for aranya_daemon_api::Role {
    fn from(value: Role) -> Self {
        match value {
            Role::Owner => Self::Owner,
            Role::Admin => Self::Admin,
            Role::Operator => Self::Operator,
            Role::Member => Self::Member,
        }
    }
}

/// A network socket address for an Aranya client.
///
/// E.g. "localhost:8080", "127.0.0.1:8080"
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct Addr(*const c_char);

impl Addr {
    unsafe fn as_underlying(self) -> Result<aranya_util::Addr, imp::Error> {
        // SAFETY: Caller must ensure the pointer is a valid C String.
        let cstr = unsafe { core::ffi::CStr::from_ptr(self.0) };
        Ok(cstr.to_str()?.parse()?)
    }
}

/// A network identifier for an Aranya client.
///
/// E.g. "localhost:8080", "127.0.0.1:8080"
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct NetIdentifier(*const c_char);

impl NetIdentifier {
    unsafe fn as_underlying(self) -> Result<aranya_daemon_api::NetIdentifier, imp::Error> {
        // SAFETY: Caller must ensure the pointer is a valid C String.
        let cstr = unsafe { core::ffi::CStr::from_ptr(self.0) };
        Ok(aranya_daemon_api::NetIdentifier(String::from(
            cstr.to_str()?,
        )))
    }
}

/// An AFC label.
///
/// It identifies the policy rules that govern the AFC channel.
#[cfg(feature = "afc")]
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct Label(u32);

#[cfg(feature = "afc")]
impl From<Label> for aranya_fast_channels::Label {
    fn from(value: Label) -> Self {
        Self::new(value.0)
    }
}

#[cfg(feature = "afc")]
impl From<aranya_fast_channels::Label> for Label {
    fn from(value: aranya_fast_channels::Label) -> Self {
        Self(value.to_u32())
    }
}

/// Sync Peer config.
#[aranya_capi_core::opaque(size = 32, align = 8)]
pub type SyncPeerConfig = Safe<imp::SyncPeerConfig>;

/// Builder for a Sync Peer config.
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 40, align = 8)]
pub type SyncPeerConfigBuilder = Safe<imp::SyncPeerConfigBuilder>;

/// A type to represent a span of time in nanoseconds.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct Duration {
    pub nanos: u64,
}

pub const ARANYA_DURATION_SECONDS: u64 = 1000 * ARANYA_DURATION_MILLISECONDS;
pub const ARANYA_DURATION_MILLISECONDS: u64 = 1000 * ARANYA_DURATION_MICROSECONDS;
pub const ARANYA_DURATION_MICROSECONDS: u64 = 1000 * ARANYA_DURATION_NANOSECONDS;
pub const ARANYA_DURATION_NANOSECONDS: u64 = 1;

impl From<Duration> for std::time::Duration {
    fn from(value: Duration) -> Self {
        std::time::Duration::from_nanos(value.nanos)
    }
}

/// Public Key bundle for a device.
#[repr(C)]
#[must_use]
#[derive(Copy, Clone, Debug)]
pub struct KeyBundle {
    /// Public identity key.
    pub ident_key: *const u8,
    /// Public identity key length.
    pub ident_key_len: usize,
    /// Public signing key.
    pub sign_key: *const u8,
    /// Public signing key length.
    pub sign_key_len: usize,
    /// Public encryption key.
    pub enc_key: *const u8,
    /// Public encryption key length.
    pub enc_key_len: usize,
}

impl KeyBundle {
    /// SAFETY: Must provide valid ptr/len "slices".
    unsafe fn as_underlying(&self) -> aranya_daemon_api::KeyBundle {
        // SAFETY: Must trust caller provides valid ptr/len.
        unsafe {
            aranya_daemon_api::KeyBundle {
                identity: slice::from_raw_parts(self.ident_key, self.ident_key_len).to_vec(),
                signing: slice::from_raw_parts(self.sign_key, self.sign_key_len).to_vec(),
                encoding: slice::from_raw_parts(self.enc_key, self.enc_key_len).to_vec(),
            }
        }
    }

    fn from_underlying(keys: aranya_daemon_api::KeyBundle) -> Self {
        // TODO: Don't leak
        let identity = keys.identity.leak();
        let signing = keys.signing.leak();
        let encoding = keys.encoding.leak();
        KeyBundle {
            ident_key: identity.as_mut_ptr(),
            ident_key_len: identity.len(),
            sign_key: signing.as_mut_ptr(),
            sign_key_len: signing.len(),
            enc_key: encoding.as_mut_ptr(),
            enc_key_len: encoding.len(),
        }
    }
}

/// Configuration info for Aranya Fast Channels.
#[cfg(feature = "afc")]
#[aranya_capi_core::opaque(size = 40, align = 8)]
pub type AfcConfig = Safe<imp::AfcConfig>;

/// Configuration info builder for Aranya Fast Channels.
#[cfg(feature = "afc")]
#[aranya_capi_core::opaque(size = 24, align = 8)]
pub type AfcConfigBuilder = imp::AfcConfigBuilder;

/// Sets the shared memory path that AFC should use for storing channel data.
///
/// @param cfg a pointer to the afc config builder
/// @param shm_path a string with the shared memory path
#[cfg(feature = "afc")]
pub fn afc_config_builder_set_shm_path(cfg: &mut AfcConfigBuilder, shm_path: *const c_char) {
    cfg.shm_path = shm_path;
}

/// Sets the maximum number of channels that are stored in shared memory.
///
/// @param cfg a pointer to the afc config builder
/// @param max_channels the maximum number of channels allowed
#[cfg(feature = "afc")]
pub fn afc_config_builder_set_max_channels(cfg: &mut AfcConfigBuilder, max_channels: usize) {
    cfg.max_channels = max_channels;
}

/// Sets the address that the AFC server should bind to for listening.
///
/// @param cfg a pointer to the afc config builder
/// @param address a string with the address to bind to
#[cfg(feature = "afc")]
pub fn afc_config_builder_set_address(cfg: &mut AfcConfigBuilder, address: *const c_char) {
    cfg.addr = address;
}

/// Attempts to construct an [`AfcConfig`], returning an `Error::Bug`
/// if there are invalid parameters.
///
/// @param cfg a pointer to the afc config builder
/// @param out a pointer to write the afc config to
#[cfg(feature = "afc")]
pub fn afc_config_builder_build(
    cfg: &mut AfcConfigBuilder,
    out: &mut MaybeUninit<AfcConfig>,
) -> Result<(), imp::Error> {
    Safe::init(out, cfg.build()?);
    Ok(())
}

/// Configuration info for Aranya.
#[aranya_capi_core::opaque(size = 48, align = 8)]
pub type ClientConfig = Safe<imp::ClientConfig>;

/// Configuration info builder for Aranya.
#[aranya_capi_core::opaque(size = 40, align = 8)]
pub type ClientConfigBuilder = imp::ClientConfigBuilder;

/// Sets the daemon address that the Client should try to connect to.
///
/// @param cfg a pointer to the client config builder
/// @param address a string containing the address
pub fn client_config_builder_set_daemon_addr(
    cfg: &mut ClientConfigBuilder,
    address: *const c_char,
) {
    cfg.daemon_addr = address;
}

/// Sets the configuration for Aranya Fast Channels.
///
/// @param cfg a pointer to the client config builder
/// @param afc_config a pointer to a valid AFC config (see [`AfcConfigBuilder`])
#[cfg(feature = "afc")]
pub fn client_config_builder_set_afc_config(
    cfg: &mut ClientConfigBuilder,
    afc_config: &mut AfcConfig,
) {
    cfg.afc = Some(**afc_config);
}

/// Attempts to construct a [`ClientConfig`], returning an `Error::Bug`
/// if there are invalid parameters.
///
/// @param cfg a pointer to the client config builder
/// @param out a pointer to write the client config to
pub fn client_config_builder_build(
    cfg: &mut ClientConfigBuilder,
    out: &mut MaybeUninit<ClientConfig>,
) -> Result<(), imp::Error> {
    Safe::init(out, cfg.build()?);
    Ok(())
}

/// Initializes a new client instance.
///
/// @param client the uninitialized Aranya Client [`Client`].
/// @param config the client's configuration [`ClientConfig`].
///
/// @relates AranyaClient.
pub unsafe fn client_init(
    client: &mut MaybeUninit<Client>,
    config: &ClientConfig,
) -> Result<(), imp::Error> {
    // TODO: Clean this up.
    let daemon_socket = OsStr::from_bytes(
        // SAFETY: Caller must ensure pointer is a valid C String.
        unsafe { std::ffi::CStr::from_ptr(config.daemon_addr) }.to_bytes(),
    )
    .as_ref();

    #[cfg(feature = "afc")]
    let afc_shm_path = OsStr::from_bytes(
        // SAFETY: Caller must ensure pointer is a valid C String.
        unsafe { std::ffi::CStr::from_ptr(config.afc.shm_path) }.to_bytes(),
    )
    .as_ref();

    #[cfg(feature = "afc")]
    let afc_addr =
        // SAFETY: Caller must ensure pointer is a valid C String.
        unsafe { std::ffi::CStr::from_ptr(config.afc.addr) }
        .to_str()?;

    let rt = tokio::runtime::Runtime::new().map_err(imp::Error::Runtime)?;

    #[cfg(feature = "afc")]
    let inner = rt.block_on(aranya_client::Client::connect(
        daemon_socket,
        afc_shm_path,
        config.afc.max_channels,
        afc_addr,
    ))?;
    #[cfg(not(feature = "afc"))]
    let inner = rt.block_on(aranya_client::Client::connect(daemon_socket))?;

    Safe::init(
        client,
        imp::Client {
            rt,
            inner,
            #[cfg(feature = "afc")]
            msg: None,
        },
    );
    Ok(())
}

/// Gets the public key bundle for this device.
///
/// @param client the Aranya Client [`Client`].
/// @param __output the client's key bundle [`KeyBundle`].
///
/// @relates AranyaClient.
pub fn get_key_bundle(client: &mut Client) -> Result<KeyBundle, imp::Error> {
    let client = client.deref_mut();
    let keys = client.rt.block_on(client.inner.get_key_bundle())?;
    Ok(KeyBundle::from_underlying(keys))
}

/// Gets the public device ID.
///
/// @param client the Aranya Client [`Client`].
/// @param __output the client's device ID [`DeviceId`].
///
/// @relates AranyaClient.
pub fn get_device_id(client: &mut Client) -> Result<DeviceId, imp::Error> {
    let client = client.deref_mut();
    let id = client.rt.block_on(client.inner.get_device_id())?;
    Ok(id.into())
}

/// Create a new graph/team with the current device as the owner.
///
/// @param client the Aranya Client [`Client`].
/// @param __output the team's ID [`TeamId`].
///
/// @relates AranyaClient.
pub fn create_team(client: &mut Client) -> Result<TeamId, imp::Error> {
    let client = client.deref_mut();
    let id = client.rt.block_on(client.inner.create_team())?;
    Ok(id.into())
}

/// Add a team to the local device store.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
///
/// @relates AranyaClient.
pub fn add_team(client: &mut Client, team: &TeamId) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(client.inner.add_team(team.into()))?;
    Ok(())
}

/// Remove a team from the local device store.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
///
/// @relates AranyaClient.
pub fn remove_team(client: &mut Client, team: &TeamId) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(client.inner.remove_team(team.into()))?;
    Ok(())
}

/// Add the peer for automatic periodic Aranya state syncing.
///
/// If a peer is not reachable on the network, sync errors
/// will appear in the tracing logs and
/// Aranya will be unable to sync state with that peer.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param addr the peer's Aranya network address [`Addr`].
/// @param config configuration values for syncing with a peer.
///
/// @relates AranyaClient.
pub unsafe fn add_sync_peer(
    client: &mut Client,
    team: &TeamId,
    addr: Addr,
    config: &SyncPeerConfig,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `addr` is a valid C String.
    let addr = unsafe { addr.as_underlying() }?;
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .add_sync_peer(addr, (**config).into()),
    )?;
    Ok(())
}

/// Sync with peer immediately.
///
/// If a peer is not reachable on the network, sync errors
/// will appear in the tracing logs and
/// Aranya will be unable to sync state with that peer.
///
///
/// This function ignores [`sync_peer_config_builder_set_interval`] and
/// [`sync_peer_config_builder_set_sync_later`], if set.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param addr the peer's Aranya network address [`Addr`].
/// @param config configuration values for syncing with a peer.
/// Default values for a sync config will be used if `config` is `NULL`
/// @relates AranyaClient.
pub unsafe fn sync_now(
    client: &mut Client,
    team: &TeamId,
    addr: Addr,
    config: Option<&SyncPeerConfig>,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `addr` is a valid C String.
    let addr = unsafe { addr.as_underlying() }?;
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .sync_now(addr, config.map(|config| (**config).into())),
    )?;
    Ok(())
}

/// Remove the peer from automatic Aranya state syncing.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param addr the peer's Aranya network address [`Addr`].
///
/// @relates AranyaClient.
pub unsafe fn remove_sync_peer(
    client: &mut Client,
    team: &TeamId,
    addr: Addr,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `addr` is a valid C String.
    let addr = unsafe { addr.as_underlying() }?;
    client
        .rt
        .block_on(client.inner.team(team.into()).remove_sync_peer(addr))?;
    Ok(())
}

/// Close the team and stop all operations on the graph.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
///
/// @relates AranyaClient.
pub fn close_team(client: &mut Client, team: &TeamId) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.team(team.into()).close_team())?;
    Ok(())
}

/// Add a device to the team with the default role.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param keys the device's public key bundle [`KeyBundle`].
///
/// @relates AranyaClient.
pub unsafe fn add_device_to_team(
    client: &mut Client,
    team: &TeamId,
    keys: &KeyBundle,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let keys =
        // SAFETY: Caller must provide valid keys.
        unsafe { keys.as_underlying() };
    client
        .rt
        .block_on(client.inner.team(team.into()).add_device_to_team(keys))?;
    Ok(())
}

/// Remove a device from the team.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
///
/// @relates AranyaClient.
pub fn remove_device_from_team(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .remove_device_from_team(device.into()),
    )?;
    Ok(())
}

/// Assign a role to a device.
///
/// This will change the device's current role to the new role assigned.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param role the role [`Role`] to assign to the device.
///
/// @relates AranyaClient.
pub fn assign_role(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    role: Role,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .assign_role(device.into(), role.into()),
    )?;
    Ok(())
}

/// Revoke a role from a device.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param role the role [`Role`] to revoke from the device.
///
/// @relates AranyaClient.
pub fn revoke_role(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    role: Role,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .revoke_role(device.into(), role.into()),
    )?;
    Ok(())
}

/// Associate a network identifier to a device for use with AQC.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// If the address already exists for this device, it is replaced with the new address. Capable
/// of resolving addresses via DNS, required to be statically mapped to IPV4. For use with
/// OpenChannel and receiving messages. Can take either DNS name or IPV4.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param net_identifier the device's network identifier [`NetIdentifier`].
///
/// @relates AranyaClient.
pub unsafe fn aqc_assign_net_identifier(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    net_identifier: NetIdentifier,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `net_identifier` is a valid C String.
    let net_identifier = unsafe { net_identifier.as_underlying() }?;
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .assign_aqc_net_identifier(device.into(), net_identifier),
    )?;
    Ok(())
}

/// Disassociate an AQC network identifier from a device.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param net_identifier the device's network identifier [`NetIdentifier`].
///
/// @relates AranyaClient.
pub unsafe fn aqc_remove_net_identifier(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    net_identifier: NetIdentifier,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `net_identifier` is a valid C String.
    let net_identifier = unsafe { net_identifier.as_underlying() }?;
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .remove_aqc_net_identifier(device.into(), net_identifier),
    )?;
    Ok(())
}

/// Create an AFC channel label.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param label the AFC channel label [`Label`] to create.
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn create_afc_label(
    client: &mut Client,
    team: &TeamId,
    label: Label,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .create_afc_label(label.into()),
    )?;
    Ok(())
}

/// Delete an AFC channel label.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param label the channel label [`Label`] to delete.
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn delete_afc_label(
    client: &mut Client,
    team: &TeamId,
    label: Label,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .delete_afc_label(label.into()),
    )?;
    Ok(())
}

/// Assign an AFC label to a device so that it can be used for an AFC channel.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device ID [`DeviceId`] of the device to assign the label to.
/// @param label the AFC channel label [`Label`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn assign_afc_label(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    label: Label,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .assign_afc_label(device.into(), label.into()),
    )?;
    Ok(())
}

/// Revoke an AFC label from a device.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device ID [`DeviceId`] of the device to revoke the label from.
/// @param label the AFC channel label [`Label`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn revoke_afc_label(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    label: Label,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .revoke_afc_label(device.into(), label.into()),
    )?;
    Ok(())
}

/// Associate an AFC network identifier to a device.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// If the address already exists for this device, it is replaced with the new address. Capable
/// of resolving addresses via DNS, required to be statically mapped to IPV4. For use with
/// OpenChannel and receiving messages. Can take either DNS name or IPV4.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param net_identifier the device's network identifier [`NetIdentifier`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub unsafe fn afc_assign_net_identifier(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    net_identifier: NetIdentifier,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `net_identifier` is a valid C String.
    let net_identifier = unsafe { net_identifier.as_underlying() }?;
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .assign_afc_net_identifier(device.into(), net_identifier),
    )?;
    Ok(())
}

/// Disassociate an AFC network identifier from a device.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param net_identifier the device's network identifier [`NetIdentifier`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub unsafe fn afc_remove_net_identifier(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    net_identifier: NetIdentifier,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `net_identifier` is a valid C String.
    let net_identifier = unsafe { net_identifier.as_underlying() }?;
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .remove_afc_net_identifier(device.into(), net_identifier),
    )?;
    Ok(())
}

/// Create an Aranya Fast Channel (AFC).
///
/// Creates a bidirectional AFC channel between the current device
/// and another peer.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param peer the peer's network identifier [`NetIdentifier`].
/// @param label the AFC channel label [`Label`] to create the channel with.
/// @param __output the channel's ID [`ChannelId`]
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub unsafe fn afc_create_bidi_channel(
    client: &mut Client,
    team: &TeamId,
    peer: NetIdentifier,
    label: Label,
) -> Result<ChannelId, imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `peer` is a valid C String.
    let peer = unsafe { peer.as_underlying() }?;
    let id = client.rt.block_on(client.inner.afc().create_bidi_channel(
        team.into(),
        peer,
        label.into(),
    ))?;
    Ok(ChannelId(id))
}

/// Delete an Aranya Fast Channel (AFC).
///
/// @param client the Aranya Client [`Client`].
/// @param chan the AFC channel ID [`ChannelId`] of the channel to delete.
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn afc_delete_channel(client: &mut Client, chan: ChannelId) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.afc().delete_channel(chan.0))?;
    Ok(())
}

/// Poll for new Aranya Fast Channels (AFC) data.
///
/// If the operation times out, this will return an `::ARANYA_ERROR_TIMEOUT`.
///
/// @param client the Aranya Client [`Client`].
/// @param timeout how long to wait before timing out the poll operation [`Duration`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn afc_poll_data(client: &mut Client, timeout: Duration) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(async {
        let data = tokio::time::timeout(timeout.into(), client.inner.afc().poll_data()).await??;
        client.inner.afc().handle_data(data).await?;
        Ok(())
    })
}

/// Send Aranya Fast Channels (AFC) data.
///
/// @param client the Aranya Client [`Client`].
/// @param chan the AFC channel's ID [`ChannelId`].
/// @param data raw bytes of data to send.
/// @param data_len length of data to send.
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn afc_send_data(client: &mut Client, chan: ChannelId, data: &[u8]) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.afc().send_data(chan.0, data))?;
    Ok(())
}

/// Aranya Fast Channels (AFC) message info.
#[repr(C)]
#[derive(Debug)]
#[cfg(feature = "afc")]
pub struct AfcMsgInfo {
    /// Uniquely (globally) identifies the channel.
    pub channel: ChannelId,
    /// The label applied to the channel.
    pub label: Label,
    /// Identifies the position of the message in the channel.
    ///
    /// This can be used to sort out-of-order messages.
    pub seq: u64,
    /// Peer's network socket address.
    pub addr: SocketAddr,
}

/// Network socket address.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
#[cfg(feature = "afc")]
pub struct SocketAddr(
    /// libc Socket address.
    // TODO: Custom type instead?
    pub  libc::sockaddr_storage,
);

#[cfg(feature = "afc")]
impl From<std::net::SocketAddr> for SocketAddr {
    fn from(value: std::net::SocketAddr) -> Self {
        let mut addr_storage =
        // SAFETY: `sockaddr_storage` is zero initializable
        unsafe { MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() };
        match value {
            std::net::SocketAddr::V4(v4) => {
                // SAFETY: `sockaddr_storage` "contains" `sockaddr_in`.
                let in4 =
                    unsafe { &mut *(ptr::from_mut(&mut addr_storage).cast::<libc::sockaddr_in>()) };
                in4.sin_family = const { libc::AF_INET as _ };
                in4.sin_port = v4.port().to_be();
                in4.sin_addr = libc::in_addr {
                    s_addr: v4.ip().to_bits().to_be(),
                };
            }
            std::net::SocketAddr::V6(v6) => {
                // SAFETY: `sockaddr_storage` "contains" `sockaddr_in6`.
                let in6 = unsafe {
                    &mut *(ptr::from_mut(&mut addr_storage).cast::<libc::sockaddr_in6>())
                };
                in6.sin6_family = const { libc::AF_INET6 as _ };
                in6.sin6_port = v6.port().to_be();
                in6.sin6_addr = libc::in6_addr {
                    s6_addr: v6.ip().to_bits().to_be_bytes(),
                };
            }
        }
        Self(addr_storage)
    }
}

/// Receive Aranya Fast Channels (AFC) data.
///
/// @param client the Aranya Client.
/// @param buf buffer to store message into.
/// @param buf_len length of buffer.
/// @param info information about the message [`AfcMsgInfo`].
/// @result A boolean indicating whether any data was available.
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub unsafe fn afc_recv_data(
    client: &mut Client,
    buf: Writer<u8>,
    info: &mut MaybeUninit<AfcMsgInfo>,
) -> Result<bool, imp::Error> {
    let client = client.deref_mut();

    if client.msg.is_none() {
        client.msg = client.inner.afc().try_recv_data();
    }
    let Some(msg) = &mut client.msg else {
        return Ok(false);
    };

    // SAFETY: The caller must ensure `buf` is valid.
    unsafe { buf.copy_to(|buf| buf.write_all(&msg.data)) }
        .map_err(|_| imp::Error::BufferTooSmall)?;

    info.write(AfcMsgInfo {
        channel: ChannelId(msg.channel),
        label: msg.label.into(),
        seq: msg.seq.to_u64(),
        addr: msg.address.into(),
    });

    client.msg = None;

    Ok(true)
}

/// Configures how often the peer will be synced with.
///
/// By default, the interval is not set. It is an error to call
/// [`sync_peer_config_builder_build`] before setting the interval with
/// this function
///
/// @param cfg a pointer to the builder for a sync config
/// @param interval Set the interval at which syncing occurs
pub fn sync_peer_config_builder_set_interval(cfg: &mut SyncPeerConfigBuilder, interval: Duration) {
    cfg.deref_mut().interval(interval);
}

/// Updates the config to enable immediate syncing with the peer.
///
/// Overrides [`sync_peer_config_builder_set_sync_later`] if invoked afterward.
///
/// By default, the peer is synced with immediately.
///
/// @param cfg a pointer to the builder for a sync config
// TODO: aranya-core#129
pub fn sync_peer_config_builder_set_sync_now(cfg: &mut SyncPeerConfigBuilder) {
    cfg.deref_mut().sync_now(true);
}

/// Updates the config to disable immediate syncing with the peer.
///
/// Overrides [`sync_peer_config_builder_set_sync_now`] if invoked afterward.
///
/// By default, the peer is synced with immediately.
/// @param cfg a pointer to the builder for a sync config
// TODO: aranya-core#129
pub fn sync_peer_config_builder_set_sync_later(cfg: &mut SyncPeerConfigBuilder) {
    cfg.deref_mut().sync_now(false);
}

/// Build a sync config from a sync config builder
///
/// @param cfg a pointer to the builder for a sync config
pub fn sync_peer_config_builder_build(
    cfg: &SyncPeerConfigBuilder,
    out: &mut MaybeUninit<SyncPeerConfig>,
) -> Result<(), imp::Error> {
    Safe::init(out, cfg.build()?);
    Ok(())
}
/// Query devices on team.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param devices returns a list of device IDs on the team [`DeviceId`].
/// @param devices_len returns the length of the devices list [`DeviceId`].
///
/// @relates AranyaClient.
pub fn query_devices_on_team(
    client: &mut Client,
    team: &TeamId,
    devices: Option<&mut MaybeUninit<DeviceId>>,
    devices_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let data = client
        .rt
        .block_on(client.inner.queries(team.into()).devices_on_team())?;
    let data = data.__data();
    let Some(devices) = devices else {
        *devices_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    };
    let out = aranya_capi_core::try_as_mut_slice!(devices, *devices_len);
    for (dst, src) in out.iter_mut().zip(data) {
        dst.write((*src).into());
    }
    if *devices_len < data.len() {
        *devices_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    }
    *devices_len = data.len();
    Ok(())
}

/// The size in bytes of an ID converted to a human-readable base58 string.
pub const ARANYA_ID_STR_LEN: u64 = (64 * 1375) / 1000 + 1;

/// Writes the human-readable encoding of `id` to `str`.
///
/// To always succeed, `str` must be at least `ARANYA_ID_STR_LEN` bytes long.
///
/// @param device ID [`Id`].
/// @param str ID string [`Id`].
/// @param str_len returns the length of `str`
///
/// @relates AranyaError.
#[aranya_capi_core::no_ext_error]
pub fn id_to_str(
    id: &Id,
    str: &mut MaybeUninit<c_char>,
    str_len: &mut usize,
) -> Result<(), imp::Error> {
    let str = aranya_capi_core::try_as_mut_slice!(str, *str_len);
    aranya_capi_core::write_c_str(str, &aranya_crypto::Id::from(id), str_len)?;
    Ok(())
}

// TODO: query_device_role

/// Query device's keybundle.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param __output the device's key bundle [`KeyBundle`].
///
/// @relates AranyaClient.
pub unsafe fn query_device_keybundle(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
) -> Result<KeyBundle, imp::Error> {
    let client = client.deref_mut();
    let keys = client.rt.block_on(
        client
            .inner
            .queries(team.into())
            .device_keybundle(device.into()),
    )?;
    Ok(KeyBundle::from_underlying(keys))
}

/// Query device label assignments.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param labels returns a list of labels assigned to the device [`Label`].
/// @param labels_len returns the length of the labels list [`Label`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn query_device_afc_label_assignments(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    labels: Option<&mut MaybeUninit<u32>>,
    labels_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let data = client.rt.block_on(
        client
            .inner
            .queries(team.into())
            .device_afc_label_assignments(device.into()),
    )?;
    let data = data.__data();
    let Some(labels) = labels else {
        *labels_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    };
    let out = aranya_capi_core::try_as_mut_slice!(labels, *labels_len);
    for (dst, src) in out.iter_mut().zip(data) {
        dst.write(src.to_u32());
    }
    if *labels_len < data.len() {
        *labels_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    }
    *labels_len = data.len();
    Ok(())
}

/// Query device's AFC network identifier.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param network identifier string [`NetIdentifier`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub unsafe fn query_afc_net_identifier(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    ident: &mut MaybeUninit<c_char>,
    ident_len: &mut usize,
) -> Result<bool, imp::Error> {
    let client = client.deref_mut();
    let Some(net_identifier) = client.rt.block_on(
        client
            .inner
            .queries(team.into())
            .afc_net_identifier(device.into()),
    )?
    else {
        return Ok(false);
    };
    let ident = aranya_capi_core::try_as_mut_slice!(ident, *ident_len);
    aranya_capi_core::write_c_str(ident, &net_identifier, ident_len)?;
    Ok(true)
}

/// Query device's AQC network identifier.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param network identifier string [`NetIdentifier`].
///
/// @relates AranyaClient.
pub unsafe fn query_aqc_net_identifier(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    ident: &mut MaybeUninit<c_char>,
    ident_len: &mut usize,
) -> Result<bool, imp::Error> {
    let client = client.deref_mut();
    let Some(net_identifier) = client.rt.block_on(
        client
            .inner
            .queries(team.into())
            .aqc_net_identifier(device.into()),
    )?
    else {
        return Ok(false);
    };
    let ident = aranya_capi_core::try_as_mut_slice!(ident, *ident_len);
    aranya_capi_core::write_c_str(ident, &net_identifier, ident_len)?;
    Ok(true)
}

/// Query device's AQC network identifier.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param __output the device's network identifier [`NetIdentifier`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub unsafe fn query_afc_label_exists(
    client: &mut Client,
    team: &TeamId,
    label: &Label,
) -> Result<bool, imp::Error> {
    let client = client.deref_mut();
    let exists = client.rt.block_on(
        client
            .inner
            .queries(team.into())
            .afc_label_exists(label.0.into()),
    )?;
    Ok(exists)
}
