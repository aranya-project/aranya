use core::{ffi::c_char, ops::DerefMut, ptr};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use aranya_capi_core::{prelude::*, ErrorCode, InvalidArg};
use aranya_client::aqc_net::{self as aqc};
use tracing::{debug, error};

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

    /// AQC library error.
    #[capi(msg = "AQC library error")]
    Aqc,

    /// Tried to do something with AQC while the server was closed.
    #[capi(msg = "AQC server closed")]
    AqcServerClosed,

    /// Tried to do something with an AQC connection when it was closed.
    #[capi(msg = "AQC connection closed")]
    AqcConnectionClosed,

    /// Failed trying to construct a new tokio runtime.
    #[capi(msg = "tokio runtime error")]
    Runtime,

    /// Unable to create configuration info.
    #[capi(msg = "invalid config")]
    Config,

    /// Serialization error.
    #[capi(msg = "serialization")]
    Serialization,

    /// Some other error occurred.
    #[capi(msg = "other")]
    Other,
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
                aranya_client::Error::Aqc(_) => Self::Aqc,
                aranya_client::Error::Bug(_) => Self::Bug,
                aranya_client::Error::Config(_) => Self::Config,
                _ => {
                    error!("Forgot to implement an error variant!");
                    Self::Bug
                }
            },
            imp::Error::Runtime(_) => Self::Runtime,
            imp::Error::Config(_) => Self::Config,
            imp::Error::Serialization(_) => Self::Serialization,
            imp::Error::AqcServerClosed => Self::AqcServerClosed,
            imp::Error::AqcConnectionClosed => Self::AqcConnectionClosed,
            imp::Error::Other(_) => Self::Other,
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
#[aranya_capi_core::opaque(size = 88, align = 8)]
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
#[aranya_capi_core::opaque(size = 3728, align = 16)]
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

impl AsRef<aranya_crypto::Id> for Id {
    fn as_ref(&self) -> &aranya_crypto::Id {
        // SAFETY: Each type is a struct with a single field containing an array of 64 bytes
        unsafe { &*ptr::from_ref::<[u8; ARANYA_ID_LEN]>(&self.bytes).cast::<aranya_crypto::Id>() }
    }
}

impl From<aranya_crypto::Id> for Id {
    fn from(value: aranya_crypto::Id) -> Self {
        Id {
            bytes: value.into(),
        }
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

/// Label ID.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct LabelId {
    id: Id,
}

impl From<aranya_daemon_api::LabelId> for LabelId {
    fn from(value: aranya_daemon_api::LabelId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&LabelId> for aranya_daemon_api::LabelId {
    fn from(value: &LabelId) -> Self {
        value.id.bytes.into()
    }
}

/// Channel ID for AQC bidi channel.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AqcBidiChannelId {
    id: Id,
}

impl From<aranya_daemon_api::AqcBidiChannelId> for AqcBidiChannelId {
    fn from(value: aranya_daemon_api::AqcBidiChannelId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&AqcBidiChannelId> for aranya_daemon_api::AqcBidiChannelId {
    fn from(value: &AqcBidiChannelId) -> Self {
        value.id.bytes.into()
    }
}

/// Channel ID for AQC uni channel.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AqcUniChannelId {
    id: Id,
}

impl From<aranya_daemon_api::AqcUniChannelId> for AqcUniChannelId {
    fn from(value: aranya_daemon_api::AqcUniChannelId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&AqcUniChannelId> for aranya_daemon_api::AqcUniChannelId {
    fn from(value: &AqcUniChannelId) -> Self {
        value.id.bytes.into()
    }
}

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

/// Valid channel operations for a label assignment.
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum ChanOp {
    /// The device can only receive data in channels with this
    /// label.
    RecvOnly,
    /// The device can only send data in channels with this
    /// label.
    SendOnly,
    /// The device can send and receive data in channels with this
    /// label.
    SendRecv,
}

impl From<ChanOp> for aranya_daemon_api::ChanOp {
    fn from(value: ChanOp) -> Self {
        match value {
            ChanOp::RecvOnly => Self::RecvOnly,
            ChanOp::SendOnly => Self::SendOnly,
            ChanOp::SendRecv => Self::SendRecv,
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

/// An AQC label name.
///
/// E.g. "TELEMETRY_LABEL"
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct LabelName(*const c_char);

impl LabelName {
    unsafe fn as_underlying(self) -> Result<String, imp::Error> {
        // SAFETY: Caller must ensure the pointer is a valid C String.
        let cstr = unsafe { core::ffi::CStr::from_ptr(self.0) };
        Ok(String::from(cstr.to_str()?))
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

/// Configuration info for Aranya QUIC Channels.
#[aranya_capi_core::opaque(size = 40, align = 8)]
pub type AqcConfig = Safe<imp::AqcConfig>;

/// Configuration info builder for Aranya QUIC Channels.
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 24, align = 8)]
pub type AqcConfigBuilder = Safe<imp::AqcConfigBuilder>;

/// Sets the address that the AQC server should bind to for listening.
///
/// @param cfg a pointer to the aqc config builder
/// @param address a string with the address to bind to
pub fn aqc_config_builder_set_address(cfg: &mut AqcConfigBuilder, address: *const c_char) {
    cfg.addr(address);
}

/// Attempts to construct an [`AqcConfig`], returning an `Error::Config`
/// if there are invalid parameters.
///
/// @param cfg a pointer to the aqc config builder
/// @param out a pointer to write the aqc config to
pub fn aqc_config_builder_build(
    cfg: &mut AqcConfigBuilder,
    out: &mut MaybeUninit<AqcConfig>,
) -> Result<(), imp::Error> {
    Safe::init(out, cfg.build()?);
    Ok(())
}

/// Configuration info for Aranya.
#[aranya_capi_core::opaque(size = 56, align = 8)]
pub type ClientConfig = Safe<imp::ClientConfig>;

/// Configuration info builder for Aranya.
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 72, align = 8)]
pub type ClientConfigBuilder = Safe<imp::ClientConfigBuilder>;

/// Sets the daemon address that the Client should try to connect to.
///
/// @param cfg a pointer to the client config builder
/// @param address a string containing the address
pub fn client_config_builder_set_daemon_addr(
    cfg: &mut ClientConfigBuilder,
    address: *const c_char,
) {
    cfg.daemon_addr(address);
}

/// Attempts to construct a [`ClientConfig`], returning an `Error::Config`
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

/// Sets the configuration for Aranya QUIC Channels.
///
/// @param cfg a pointer to the client config builder
/// @param aqc_config a pointer to a valid AQC config (see [`AqcConfigBuilder`])
pub fn client_config_builder_set_aqc_config(cfg: &mut ClientConfigBuilder, aqc_config: &AqcConfig) {
    cfg.aqc(**aqc_config);
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
        unsafe { std::ffi::CStr::from_ptr(config.daemon_addr()) }.to_bytes(),
    )
    .as_ref();

    let rt = tokio::runtime::Runtime::new().map_err(imp::Error::Runtime)?;

    let inner = rt.block_on(aranya_client::Client::connect(
        daemon_socket,
        // SAFETY: Caller ensures config.aqc().addr is valid
        unsafe { NetIdentifier(config.aqc().addr).as_underlying()? },
    ))?;

    Safe::init(client, imp::Client { rt, inner });
    Ok(())
}

/// Gets the public key bundle for this device.
///
/// @param client the Aranya Client [`Client`].
/// @param keybundle keybundle byte buffer `KeyBundle`.
/// @param keybundle_len returns the length of the serialized keybundle.
///
/// @relates AranyaClient.
pub unsafe fn get_key_bundle(
    client: &mut Client,
    keybundle: *mut MaybeUninit<u8>,
    keybundle_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let keys = client.rt.block_on(client.inner.get_key_bundle())?;
    // SAFETY: Must trust caller provides valid ptr/len for keybundle buffer.
    unsafe { imp::key_bundle_serialize(&keys, keybundle, keybundle_len)? };

    Ok(())
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

#[aranya_capi_core::opaque(size = 24, align = 8)]
pub type TeamConfig = Safe<imp::TeamConfig>;

#[aranya_capi_core::opaque(size = 16, align = 8)]
pub type TeamConfigBuilder = Safe<imp::TeamConfigBuilder>;

/// Attempts to construct a [`TeamConfig`], returning an `Error::Config`
/// if there are invalid parameters.
///
/// @param cfg a pointer to the team config builder
/// @param out a pointer to write the team config to
pub fn team_config_builder_build(
    cfg: &mut TeamConfigBuilder,
    out: &mut MaybeUninit<TeamConfig>,
) -> Result<(), imp::Error> {
    Safe::init(out, cfg.build()?);
    Ok(())
}

/// Create a new graph/team with the current device as the owner.
///
/// @param client the Aranya Client [`Client`].
/// @param cfg the Team Configuration [`TeamConfig`].
/// @param __output the team's ID [`TeamId`].
///
/// @relates AranyaClient.
#[allow(unused_variables)] // TODO(nikki): once we have fields on TeamConfig, remove this for cfg
pub fn create_team(client: &mut Client, cfg: &TeamConfig) -> Result<TeamId, imp::Error> {
    let client = client.deref_mut();
    let cfg = aranya_client::TeamConfig::builder().build()?;
    let id = client.rt.block_on(client.inner.create_team(cfg))?;
    Ok(id.into())
}

/// Add a team to the local device store.
///
/// NOTE: this function is unfinished and will panic if called.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param cfg the Team Configuration [`TeamConfig`].
///
/// @relates AranyaClient.
#[allow(unused_variables)] // TODO(nikki): once we have fields on TeamConfig, remove this for cfg
pub fn add_team(client: &mut Client, team: &TeamId, cfg: &TeamConfig) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let cfg = aranya_client::TeamConfig::builder().build()?;
    client
        .rt
        .block_on(client.inner.add_team(team.into(), cfg))?;
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
/// @param keybundle serialized keybundle byte buffer `KeyBundle`.
/// @param keybundle_len is the length of the serialized keybundle.
///
/// @relates AranyaClient.
pub unsafe fn add_device_to_team(
    client: &mut Client,
    team: &TeamId,
    keybundle: &[u8],
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let keybundle = imp::key_bundle_deserialize(keybundle)?;

    client
        .rt
        .block_on(client.inner.team(team.into()).add_device_to_team(keybundle))?;
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

/// Create a channel label.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param name label name string [`LabelName`].
///
/// @relates AranyaClient.
pub fn create_label(
    client: &mut Client,
    team: &TeamId,
    name: LabelName,
) -> Result<LabelId, imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `name` is a valid C String.
    let name = unsafe { name.as_underlying() }?;
    let label_id = client
        .rt
        .block_on(client.inner.team(team.into()).create_label(name))?;
    Ok(label_id.into())
}

/// Delete a channel label.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param label_id the channel label ID [`LabelId`] to delete.
///
/// @relates AranyaClient.
pub fn delete_label(
    client: &mut Client,
    team: &TeamId,
    label_id: &LabelId,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.team(team.into()).delete_label(label_id.into()))?;
    Ok(())
}

/// Assign a label to a device so that it can be used for a channel.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device ID [`DeviceId`] of the device to assign the label to.
/// @param label_id the AQC channel label ID [`LabelId`].
///
/// @relates AranyaClient.
pub fn assign_label(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    label_id: &LabelId,
    op: ChanOp,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.team(team.into()).assign_label(
            device.into(),
            label_id.into(),
            op.into(),
        ))?;
    Ok(())
}

/// Revoke a label from a device.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device ID [`DeviceId`] of the device to revoke the label from.
/// @param label_id the AQC channel label ID [`LabelId`].
///
/// @relates AranyaClient.
pub fn revoke_label(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    label_id: &LabelId,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .revoke_label(device.into(), label_id.into()),
    )?;
    Ok(())
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
    if *devices_len < data.len() {
        *devices_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    }
    for (dst, src) in out.iter_mut().zip(data) {
        dst.write((*src).into());
    }
    *devices_len = data.len();
    Ok(())
}

/// The size in bytes of an ID converted to a human-readable base58 string.
pub const ARANYA_ID_STR_LEN: usize = (ARANYA_ID_LEN * 1375) / 1000 + 1;

/// Writes the human-readable encoding of `id` to `str`.
///
/// To always succeed, `str` must be at least `ARANYA_ID_STR_LEN` bytes long.
///
/// @param device ID [`Id`].
/// @param str ID string [`Id`].
/// @param str_len returns the length of `str`
///
/// @relates AranyaId.
#[aranya_capi_core::no_ext_error]
pub fn id_to_str(
    id: &Id,
    str: &mut MaybeUninit<c_char>,
    str_len: &mut usize,
) -> Result<(), imp::Error> {
    let str = aranya_capi_core::try_as_mut_slice!(str, *str_len);
    aranya_capi_core::write_c_str(str, id.as_ref(), str_len)?;
    Ok(())
}

/// Decodes `str` into an [`Id`].
///
///
/// @param str pointer to a null-terminated string.
///
/// @relates AranyaId.
#[aranya_capi_core::no_ext_error]
pub unsafe fn id_from_str(str: *const c_char) -> Result<Id, imp::Error> {
    // SAFETY: Caller must ensure the pointer is a valid C String.
    let cstr = unsafe { std::ffi::CStr::from_ptr(str) };

    aranya_crypto::Id::decode(cstr.to_bytes())
        .map_err(|_| InvalidArg::new("str", "unable to decode ID from bytes").into())
        .map(Into::into)
}

// TODO: query_device_role

/// Query device's keybundle.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param keybundle keybundle byte buffer `KeyBundle`.
/// @param keybundle_len returns the length of the serialized keybundle.
///
/// @relates AranyaClient.
pub unsafe fn query_device_keybundle(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    keybundle: *mut MaybeUninit<u8>,
    keybundle_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let keys = client.rt.block_on(
        client
            .inner
            .queries(team.into())
            .device_keybundle(device.into()),
    )?;
    // SAFETY: Must trust caller provides valid ptr/len for keybundle buffer.
    unsafe { imp::key_bundle_serialize(&keys, keybundle, keybundle_len)? };
    Ok(())
}

/// Query device label assignments.
///
/// Returns an `AranyaBufferTooSmall` error if the output buffer is too small to hold the labels.
/// Writes the number of labels that would have been returned to `labels_len`.
/// The application can use `labels_len` to allocate a larger buffer.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
///
/// Output params:
/// @param labels returns a list of labels assigned to the device [`LabelId`].
/// @param labels_len returns the length of the labels list [`LabelId`].
///
/// @relates AranyaClient.
pub fn query_device_label_assignments(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    labels: Option<&mut MaybeUninit<LabelId>>,
    labels_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let data = client.rt.block_on(
        client
            .inner
            .queries(team.into())
            .device_label_assignments(device.into()),
    )?;
    let data = data.__data();
    let Some(labels) = labels else {
        *labels_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    };
    let out = aranya_capi_core::try_as_mut_slice!(labels, *labels_len);
    if *labels_len < data.len() {
        *labels_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    }
    for (dst, src) in out.iter_mut().zip(data) {
        dst.write(src.id.into());
    }
    *labels_len = data.len();
    Ok(())
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

/// Query if a label exists.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param label the label [`LabelId`].
/// @param __output boolean indicating whether the label exists.
///
/// @relates AranyaClient.
pub unsafe fn query_label_exists(
    client: &mut Client,
    team: &TeamId,
    label: &LabelId,
) -> Result<bool, imp::Error> {
    let client = client.deref_mut();
    let exists = client
        .rt
        .block_on(client.inner.queries(team.into()).label_exists(label.into()))?;
    Ok(exists)
}

/// Query for list of existing labels.
///
/// Returns an `AranyaBufferTooSmall` error if the output buffer is too small to hold the labels.
/// Writes the number of labels that would have been returned to `labels_len`.
/// The application can use `labels_len` to allocate a larger buffer.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
///
/// Output params:
/// @param labels returns a list of labels [`LabelId`].
/// @param labels_len returns the length of the labels list [`LabelId`].
///
/// @relates AranyaClient.
pub fn query_labels(
    client: &mut Client,
    team: &TeamId,
    labels: Option<&mut MaybeUninit<LabelId>>,
    labels_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let data = client
        .rt
        .block_on(client.inner.queries(team.into()).labels())?;
    let data = data.__data();
    let Some(labels) = labels else {
        *labels_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    };
    let out = aranya_capi_core::try_as_mut_slice!(labels, *labels_len);
    for (dst, src) in out.iter_mut().zip(data) {
        dst.write(src.id.into());
    }
    if *labels_len < data.len() {
        *labels_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    }
    *labels_len = data.len();
    Ok(())
}

/// A type containing the AQC channel variant.
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 192, align = 8)]
pub type AqcChannel = Safe<imp::AqcChannelType>;

/// An enum containing all [`AqcChannel`] variants.
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum AqcChannelType {
    Sender,
    Receiver,
    Bidirectional,
}

/// AQC Bidirectional Channel Object
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 184, align = 8)]
pub type AqcBidiChannel = Safe<imp::AqcBidiChannel>;

/// AQC Sender Channel Object
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 176, align = 8)]
pub type AqcSenderChannel = Safe<imp::AqcSenderChannel>;

/// AQC Receiver Channel Object
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 152, align = 8)]
pub type AqcReceiverChannel = Safe<imp::AqcReceiverChannel>;

/// AQC Sender Stream Object
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 152, align = 8)]
pub type AqcSendStream = Safe<imp::AqcSendStream>;

/// AQC Sender Stream Object
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 152, align = 8)]
pub type AqcReceiveStream = Safe<imp::AqcReceiveStream>;

/// Create a bidirectional AQC channel between this device and another peer.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param peer the peer's network identifier [`NetIdentifier`].
/// @param label_id the AQC channel label ID [`LabelId`] to create the channel with.
/// @param channel the AQC channel object [`AqcBidiChannel`] that holds channel info.
///
/// @relates AranyaClient.
pub unsafe fn aqc_create_bidi_channel(
    client: &mut Client,
    team: &TeamId,
    peer: NetIdentifier,
    label_id: &LabelId,
    channel: &mut MaybeUninit<AqcBidiChannel>,
) -> Result<(), imp::Error> {
    // SAFETY: Caller must ensure `peer` is a valid C String.
    let peer = unsafe { peer.as_underlying() }?;

    let client = client.deref_mut();
    let chan = client.rt.block_on(client.inner.aqc().create_bidi_channel(
        team.into(),
        peer,
        label_id.into(),
    ))?;

    Safe::init(channel, imp::AqcBidiChannel::new(chan));

    Ok(())
}

/// Delete a bidirectional AQC channel.
///
/// @param client the Aranya Client [`Client`].
/// @param channel_id the AQC Channel [`AqcBidiChannel`] to delete.
///
/// @relates AranyaClient.
pub fn aqc_delete_bidi_channel(
    client: &mut Client,
    channel: &AqcBidiChannelId,
) -> Result<(), imp::Error> {
    // TODO(nikki): change to AqcBidiChannel
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.aqc().delete_bidi_channel(channel.into()))?;
    Ok(())
}

/// Waits until an AQC channel is received from the client.
///
/// Returns `ARANYA_ERROR_AQC_SERVER_CLOSED` if trying to call this when the
/// server connection has been closed.
/// 
/// @param client the Aranya Client [`Client`].
/// @param channel the AQC channel holder [`AqcChannel`] that holds a channel object.
pub fn aqc_receive_channel(
    client: &mut Client,
    channel: &mut MaybeUninit<AqcChannel>,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let chan = client
        .rt
        .block_on(client.inner.aqc().receive_channel())
        .ok_or(imp::Error::AqcServerClosed)?;

    Safe::init(channel, imp::AqcChannelType::new(chan));

    Ok(())
}

/// Returns the [`AqcChannelType`] for a given [`AqcChannel`] for matching.
///
/// # Example
/// ```C
/// AqcChannel channel;
/// AqcBidiChannel bidi;
/// AqcSenderChannel sender;
/// AqcReceiverChannel receiver;
/// switch (aranya_aqc_get_channel_type(channel)) {
///     case ARANYA_AQC_CHANNEL_TYPE_BIDIRECTIONAL:
///         aranya_aqc_get_bidirectional_channel(channel, &bidi);
///         break;
///     case ARANYA_AQC_CHANNEL_TYPE_SENDER:
///         aranya_aqc_get_sender_channel(channel, &sender);
///         break;
///     case ARANYA_AQC_CHANNEL_TYPE_RECEIVER:
///         aranya_aqc_get_receiver_channel(channel, &receiver);
///         break;
/// }
/// ```
///
/// @param channel the AQC channel holder [`AqcChannel`] that holds a channel object.
/// @param __output the corresponding AQC channel type [`AqcChannelType`] to match against.
pub fn aqc_get_channel_type(channel: &mut AqcChannel) -> AqcChannelType {
    match channel.inner {
        aqc::AqcChannelType::Bidirectional { .. } => AqcChannelType::Bidirectional,
        aqc::AqcChannelType::Sender { .. } => AqcChannelType::Sender,
        aqc::AqcChannelType::Receiver { .. } => AqcChannelType::Receiver,
    }
}

/// Converts the [`AqcChannel`]` into an [`AqcBidiChannel`] for further use.
///
/// Returns `ARANYA_ERROR_INVALID_ARGUMENT` if called when the AqcChannel is the wrong type.
///
/// @param channel the AQC channel holder [`AqcChannel`] that holds a channel object.
/// @param bidi the AQC channel object [`AqcBidiChannel`] that holds channel info.
pub fn aqc_get_bidirectional_channel(
    channel: AqcChannel,
    bidi: &mut MaybeUninit<AqcBidiChannel>,
) -> Result<(), imp::Error> {
    match channel.into_inner().inner {
        aqc::AqcChannelType::Bidirectional { channel } => {
            Safe::init(bidi, imp::AqcBidiChannel::new(channel));
        }
        _ => {
            let e = InvalidArg::new(
                "channel",
                "Tried to call get_bidirectional_channel with a `AqcChannel` that wasn't Bidirectional!",
            );
            return Err(e.into());
        }
    }

    Ok(())
}

/// Converts the [`AqcChannel`]` into an [`AqcSenderChannel`] for further use.
///
/// Returns `ARANYA_ERROR_INVALID_ARGUMENT` if called when the AqcChannel is the wrong type.
///
/// @param channel the AQC channel holder [`AqcChannel`] that holds a channel object.
/// @param sender the AQC channel object [`AqcSenderChannel`] that holds channel info.
pub fn aqc_get_sender_channel(
    channel: AqcChannel,
    sender: &mut MaybeUninit<AqcSenderChannel>,
) -> Result<(), imp::Error> {
    match channel.into_inner().inner {
        aqc::AqcChannelType::Sender { sender: send } => {
            Safe::init(sender, imp::AqcSenderChannel::new(send));
        }
        _ => {
            let e = InvalidArg::new(
                "channel",
                "Tried to call get_receiver_channel with a `AqcChannel` that wasn't a receiver!",
            );
            return Err(e.into());
        }
    }

    Ok(())
}

/// Converts the [`AqcChannel`]` into an [`AqcReceiverChannel`] for further use.
///
/// Returns `ARANYA_ERROR_INVALID_ARGUMENT` if called when the AqcChannel is the wrong type.
///
/// @param channel the AQC channel holder [`AqcChannel`] that holds a channel object.
/// @param receiver the AQC channel object [`AqcReceiverChannel`] that holds channel info.
pub fn aqc_get_receiver_channel(
    channel: AqcChannel,
    receiver: &mut MaybeUninit<AqcReceiverChannel>,
) -> Result<(), imp::Error> {
    match channel.into_inner().inner {
        aqc::AqcChannelType::Receiver { receiver: recv } => {
            Safe::init(receiver, imp::AqcReceiverChannel::new(recv));
        }
        _ => {
            let e = InvalidArg::new(
                "channel",
                "Tried to call get_receiver_channel with a `AqcChannel` that wasn't a receiver!",
            );
            return Err(e.into());
        }
    }

    Ok(())
}

/// Create a bidirectional stream from an [`AqcBidiChannel`].
/// 
/// @param client the Aranya Client [`Client`].
/// @param channel the AQC channel object [`AqcBidiChannel`] that holds channel info.
/// @param send_stream the sending side of a stream [`AqcSendStream`].
/// @param recv_stream the receiving side of a stream [`AqcReceiveStream`].
pub fn aqc_bidi_create_bidi_stream(
    client: &mut Client,
    channel: &mut AqcBidiChannel,
    send_stream: &mut MaybeUninit<AqcSendStream>,
    recv_stream: &mut MaybeUninit<AqcReceiveStream>,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let (send, recv) = client
        .rt
        .block_on(channel.inner.create_bidirectional_stream())?;

    Safe::init(send_stream, imp::AqcSendStream::new(send));
    Safe::init(recv_stream, imp::AqcReceiveStream::new(recv));

    Ok(())
}

/// Create a unidirectional stream from an [`AqcBidiChannel`].
/// 
/// @param client the Aranya Client [`Client`].
/// @param channel the AQC channel object [`AqcBidiChannel`] that holds channel info.
/// @param send_stream the sending side of a stream [`AqcSendStream`].
pub fn aqc_bidi_create_uni_stream(
    client: &mut Client,
    channel: &mut AqcBidiChannel,
    send_stream: &mut MaybeUninit<AqcSendStream>,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let send = client
        .rt
        .block_on(channel.inner.create_unidirectional_stream())?;

    Safe::init(send_stream, imp::AqcSendStream::new(send));

    Ok(())
}

/// Receives the receiving end of a stream and potentially the sending end of
/// another stream.
/// 
/// Note that the send stream will only be initialized if this returns true.
/// 
/// @param client the Aranya Client [`Client`].
/// @param channel the AQC channel object [`AqcBidiChannel`] that holds channel info.
/// @param send_stream the sending side of a stream [`AqcSendStream`].
/// @param recv_stream the receiving side of a stream [`AqcReceiveStream`].
/// @param __output returns whether we received an [`AqcSendStream`] or not.
pub fn aqc_bidi_receive_stream(
    client: &mut Client,
    channel: &mut AqcBidiChannel,
    send_stream: &mut MaybeUninit<AqcSendStream>,
    recv_stream: &mut MaybeUninit<AqcReceiveStream>,
) -> Result<bool, imp::Error> {
    let client = client.deref_mut();
    let (send, recv) = client
        .rt
        .block_on(channel.inner.receive_stream())
        .ok_or(imp::Error::AqcConnectionClosed)?;

    Safe::init(recv_stream, imp::AqcReceiveStream::new(recv));
    match send {
        Some(send) => {
            Safe::init(send_stream, imp::AqcSendStream::new(send));
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Create a unidirectional stream from an [`AqcSenderChannel`].
/// 
/// @param client the Aranya Client [`Client`].
/// @param channel the AQC channel object [`AqcSenderChannel`] that holds channel info.
/// @param send_stream the sending side of a stream [`AqcSendStream`].
pub fn aqc_send_create_uni_stream(
    client: &mut Client,
    channel: &mut AqcSenderChannel,
    send_stream: &mut MaybeUninit<AqcSendStream>,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let send = client
        .rt
        .block_on(channel.inner.create_unidirectional_stream())?;

    Safe::init(send_stream, imp::AqcSendStream::new(send));

    Ok(())
}

/// Receives the stream from an [`AqcReceiverChannel`].
/// 
/// @param client the Aranya Client [`Client`].
/// @param channel the AQC channel object [`AqcReceiverChannel`] that holds channel info.
/// @param recv_stream the receiving side of a stream [`AqcReceiveStream`].
pub fn aqc_recv_receive_uni_stream(
    client: &mut Client,
    channel: &mut AqcReceiverChannel,
    recv_stream: &mut MaybeUninit<AqcReceiveStream>,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let recv = client
        .rt
        .block_on(channel.inner.receive_unidirectional_stream())?
        .ok_or(imp::Error::AqcConnectionClosed)?;

    Safe::init(recv_stream, imp::AqcReceiveStream::new(recv));

    Ok(())
}

/*
TODO(nikki): AQC uni support
/// Unidirectional AQC Channel Object
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 184, align = 8)]
pub type AqcUniChannel = Safe<imp::AqcUniChannel>;

/// Create a unidirectional AQC channel between this device and another peer.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param peer the peer's network identifier [`NetIdentifier`].
/// @param label_id the AQC channel label ID [`LabelId`] to create the channel with.
/// @param channel the AQC channel object [`AqcUniChannel`] that holds channel info.
///
/// @relates AranyaClient.
pub unsafe fn aqc_create_uni_channel(
    client: &mut Client,
    team: &TeamId,
    peer: NetIdentifier,
    label_id: &LabelId,
    channel: &mut MaybeUninit<AqcUniChannel>,
) -> Result<(), imp::Error> {
    // SAFETY: Caller must ensure `peer` is a valid C String.
    let peer = unsafe { peer.as_underlying() }?;

    let client = client.deref_mut();
    let (chan, _) = client.rt.block_on(client.inner.aqc().create_uni_channel(
        team.into(),
        peer,
        label_id.into(),
    ))?;

    Safe::init(channel, imp::AqcUniChannel::new(chan));

    Ok(())
}

/// Delete a unidirectional AQC channel.
///
/// @param client the Aranya Client [`Client`].
/// @param chan the AQC Channel [`AqcUniChannel`] to delete.
///
/// @relates AranyaClient.
pub fn aqc_delete_uni_channel(
    client: &mut Client,
    channel: &AqcUniChannel,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.aqc().delete_uni_channel(channel.into()))?;
    Ok(())
}
*/
