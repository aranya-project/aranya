use core::{
    ffi::{c_char, CStr},
    ops::{Deref, DerefMut},
    ptr,
};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use anyhow::Context as _;
use aranya_capi_core::{prelude::*, ErrorCode, InvalidArg};
use aranya_crypto::hex;
use tracing::error;

use super::AranyaOp;
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

    /// Could not send request to daemon.
    #[capi(msg = "could not send request to daemon")]
    Ipc,

    /// An Aranya error.
    #[capi(msg = "Aranya error")]
    Aranya,

    /// AQC library error.
    #[capi(msg = "AQC library error")]
    Aqc,

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
        error!(?err);
        match err {
            imp::Error::Bug(_) => Self::Bug,
            imp::Error::Timeout(_) => Self::Timeout,
            imp::Error::InvalidArg(_) => Self::InvalidArgument,
            imp::Error::Utf8(_) => Self::InvalidUtf8,
            imp::Error::Addr(_) => Self::InvalidAddr,
            imp::Error::BufferTooSmall => Self::BufferTooSmall,
            imp::Error::Client(err) => match err {
                aranya_client::Error::Ipc(_) => Self::Ipc,
                aranya_client::Error::Aranya(_) => Self::Aranya,
                aranya_client::Error::Aqc(_) => Self::Aqc,
                aranya_client::Error::Bug(_) => Self::Bug,
                aranya_client::Error::Config(_) => Self::Config,
                aranya_client::Error::Other(_) => Self::Other,
                _ => {
                    error!("forgot to implement an error variant");
                    Self::Bug
                }
            },
            imp::Error::Config(_) => Self::Config,
            imp::Error::Serialization(_) => Self::Serialization,
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
        unsafe { CStr::from_ptr(config.daemon_addr()) }.to_bytes(),
    )
    .as_ref();

    let rt = tokio::runtime::Runtime::new().context("unable to construct tokio runtime")?;

    let inner = rt.block_on({
        aranya_client::Client::builder()
            .with_daemon_uds_path(daemon_socket)
            .with_daemon_api_pk(config.daemon_api_pk())
            .connect()
    })?;

    Safe::init(client, imp::Client { rt, inner });
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
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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

impl From<aranya_client::TeamId> for TeamId {
    fn from(value: aranya_client::TeamId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&TeamId> for aranya_client::TeamId {
    fn from(value: &TeamId) -> Self {
        value.id.bytes.into()
    }
}

/// Device ID.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceId {
    id: Id,
}

impl From<aranya_client::DeviceId> for DeviceId {
    fn from(value: aranya_client::DeviceId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&DeviceId> for aranya_client::DeviceId {
    fn from(value: &DeviceId) -> Self {
        value.id.bytes.into()
    }
}

/// Role ID.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RoleId {
    id: Id,
}

impl From<aranya_client::RoleId> for RoleId {
    fn from(value: aranya_client::RoleId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&RoleId> for aranya_client::RoleId {
    fn from(value: &RoleId) -> Self {
        value.id.bytes.into()
    }
}

/// Label ID.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct LabelId {
    id: Id,
}

impl From<aranya_client::LabelId> for LabelId {
    fn from(value: aranya_client::LabelId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&LabelId> for aranya_client::LabelId {
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

impl From<aranya_client::aqc::BidiChannelId> for AqcBidiChannelId {
    fn from(value: aranya_client::aqc::BidiChannelId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&AqcBidiChannelId> for aranya_client::aqc::BidiChannelId {
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

impl From<aranya_client::aqc::UniChannelId> for AqcUniChannelId {
    fn from(value: aranya_client::aqc::UniChannelId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

impl From<&AqcUniChannelId> for aranya_client::aqc::UniChannelId {
    fn from(value: &AqcUniChannelId) -> Self {
        value.id.bytes.into()
    }
}

/// Valid operations that roles can perform.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Op {
    /// Add a member device to team.
    AddMember,
    /// Remove a member device from team.
    RemoveMember,
    /// Assign device precedence to a device.
    AssignDevicePrecedence,
    /// Create a role on team.
    CreateRole,
    /// Delete a role from team.
    DeleteRole,
    /// Setup admin role.
    SetupAdminRole,
    /// Setup operator role.
    SetupOperatorRole,
    /// Setup member role.
    SetupMemberRole,
    /// Assign a role to a device.
    AssignRole,
    /// Revoke a role from a device.
    RevokeRole,
    /// Assign operation to a role.
    AssignRoleOp,
    /// Revoke operation from a role.
    RevokeRoleOp,
    /// Create a label on team.
    CreateLabel,
    /// Delete a label from team.
    DeleteLabel,
    /// Assign a label to a device.
    AssignLabel,
    /// Revoke a label from a device.
    RevokeLabel,
    /// Set an AQC network name.
    SetAqcNetworkName,
    /// Unset an AQC network name.
    UnsetAqcNetworkName,
    /// Create an AQC bidi channel.
    AqcCreateBidiChannel,
    /// Create an AQC uni channel.
    AqcCreateUniChannel,
}

impl From<Op> for aranya_client::Op {
    fn from(value: Op) -> Self {
        match value {
            Op::AddMember => Self::AddMember,
            Op::RemoveMember => Self::RemoveMember,
            Op::AssignDevicePrecedence => Self::AssignDevicePrecedence,
            Op::CreateRole => Self::CreateRole,
            Op::DeleteRole => Self::DeleteRole,
            Op::SetupAdminRole => Self::SetupAdminRole,
            Op::SetupOperatorRole => Self::SetupOperatorRole,
            Op::SetupMemberRole => Self::SetupMemberRole,
            Op::AssignRole => Self::AssignRole,
            Op::RevokeRole => Self::RevokeRole,
            Op::AssignRoleOp => Self::AssignRoleOp,
            Op::RevokeRoleOp => Self::RevokeRoleOp,
            Op::CreateLabel => Self::CreateLabel,
            Op::DeleteLabel => Self::DeleteLabel,
            Op::AssignLabel => Self::AssignLabel,
            Op::RevokeLabel => Self::RevokeLabel,
            Op::SetAqcNetworkName => Self::SetAqcNetworkName,
            Op::UnsetAqcNetworkName => Self::UnsetAqcNetworkName,
            Op::AqcCreateBidiChannel => Self::AqcCreateBidiChannel,
            Op::AqcCreateUniChannel => Self::AqcCreateUniChannel,
        }
    }
}

impl From<aranya_client::Op> for Op {
    fn from(value: aranya_client::Op) -> Self {
        use aranya_client::Op::*;
        match value {
            AddMember => Self::AddMember,
            RemoveMember => Self::RemoveMember,
            AssignDevicePrecedence => Self::AssignDevicePrecedence,
            CreateRole => Self::CreateRole,
            DeleteRole => Self::DeleteRole,
            SetupAdminRole => Self::SetupAdminRole,
            SetupMemberRole => Self::SetupMemberRole,
            SetupOperatorRole => Self::SetupOperatorRole,
            AssignRole => Self::AssignRole,
            RevokeRole => Self::RevokeRole,
            AssignRoleOp => Self::AssignRoleOp,
            RevokeRoleOp => Self::RevokeRoleOp,
            CreateLabel => Self::CreateLabel,
            DeleteLabel => Self::DeleteLabel,
            AssignLabel => Self::AssignLabel,
            RevokeLabel => Self::RevokeLabel,
            SetAqcNetworkName => Self::SetAqcNetworkName,
            UnsetAqcNetworkName => Self::UnsetAqcNetworkName,
            AqcCreateBidiChannel => Self::AqcCreateBidiChannel,
            AqcCreateUniChannel => Self::AqcCreateUniChannel,
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

impl From<ChanOp> for aranya_client::ChanOp {
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
        let cstr = unsafe { CStr::from_ptr(self.0) };
        Ok(cstr.to_str()?.parse()?)
    }
}

/// A network identifier for an Aranya client.
///
/// E.g. "localhost:8080", "127.0.0.1:8080"
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct NetIdentifier(*const c_char);

impl<'a> TryFrom<NetIdentifier> for aranya_client::NetIdentifier<'a> {
    type Error = aranya_client::InvalidNetIdentifier;

    fn try_from(id: NetIdentifier) -> Result<Self, Self::Error> {
        // SAFETY: We have to trust that the pointer is a valid
        // C string.
        let cstr = unsafe { CStr::from_ptr(id.0) };
        aranya_client::NetIdentifier::try_from(cstr)
    }
}

/// A role name.
///
/// E.g. "owner"
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct RoleName(*const c_char);

impl RoleName {
    unsafe fn as_underlying(self) -> Result<String, imp::Error> {
        // SAFETY: Caller must ensure the pointer is a valid C String.
        let cstr = unsafe { CStr::from_ptr(self.0) };
        Ok(String::from(cstr.to_str()?))
    }
}

/// A device precedence.
///
/// Determines whether the author of a graph command has permission
/// to execute a command on a target device with lower priority.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct DevicePrecedence(i64);

/// An AQC label name.
///
/// E.g. "TELEMETRY_LABEL"
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct LabelName(*const c_char);

impl LabelName {
    unsafe fn as_underlying(self) -> Result<String, imp::Error> {
        // SAFETY: Caller must ensure the pointer is a valid C String.
        let cstr = unsafe { CStr::from_ptr(self.0) };
        Ok(String::from(cstr.to_str()?))
    }
}

/// A role.
#[aranya_capi_core::opaque(size = 96, align = 8)]
pub type Role = Safe<imp::Role>;
const _: [(); 96] = [(); size_of::<Role>()];

/// A label.
#[aranya_capi_core::opaque(size = 96, align = 8)]
pub type Label = Safe<imp::Label>;
const _: [(); 96] = [(); size_of::<Label>()];

/// Sync Peer config.
#[aranya_capi_core::opaque(size = 32, align = 8)]
pub type SyncPeerConfig = Safe<imp::SyncPeerConfig>;

/// Builder for a Sync Peer config.
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 40, align = 8)]
pub type SyncPeerConfigBuilder = Safe<imp::SyncPeerConfigBuilder>;

/// Initializes logging.
///
/// Assumes the `ARANYA_CAPI` environment variable has been set to the desired tracing log level.
/// E.g. `ARANYA_CAPI=debug`.
// TODO(eric): don't make users use env vars.
pub fn init_logging() -> Result<(), imp::Error> {
    use tracing_subscriber::{prelude::*, EnvFilter};
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_env("ARANYA_CAPI"))
        .try_init()
        .context("unable to initialize logging")?;
    Ok(())
}

/// Decodes the hexadecimal string `src` into `dst` and returns
/// the number of bytes written to `dst`.
///
/// If `src` is a valid hexadecimal string, the number of bytes
/// written to `dst` will be exactly half the length of `src`.
/// Therefore, `dst` must be at least half as long as `src`.
///
/// @param dst the output buffer
/// @param src the input hexadecimal string
pub fn decode_hex(dst: &mut [u8], src: &[u8]) -> Result<usize, imp::Error> {
    hex::ct_decode(dst, src).map_err(|err| match err {
        hex::Error::InvalidLength => imp::Error::BufferTooSmall,
        hex::Error::InvalidEncoding => {
            imp::Error::InvalidArg(InvalidArg::new("src", "not a valid hexadecimal string"))
        }
        hex::Error::Bug(err) => imp::Error::Bug(err),
    })
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
    let cstr = unsafe { CStr::from_ptr(str) };

    aranya_crypto::Id::decode(cstr.to_bytes())
        .map_err(|_| InvalidArg::new("str", "unable to decode ID from bytes").into())
        .map(Into::into)
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

/// Configuration info for Aranya.
#[aranya_capi_core::opaque(size = 56, align = 8)]
pub type ClientConfig = Safe<imp::ClientConfig>;

/// Configuration info builder for Aranya.
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 72, align = 8)]
pub type ClientConfigBuilder = Safe<imp::ClientConfigBuilder>;

/// Attempts to construct a [`ClientConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param cfg a pointer to the client config builder
/// @param out a pointer to write the client config to
pub fn client_config_build(
    cfg: OwnedPtr<ClientConfigBuilder>,
    out: &mut MaybeUninit<ClientConfig>,
) -> Result<(), imp::Error> {
    // SAFETY: No special considerations.
    unsafe { cfg.build(out)? }
    Ok(())
}

/// Sets Unix Domain Socket path that the daemon is listening on.
///
/// @param cfg a pointer to the client config builder
/// @param address a string containing the address
pub fn client_config_builder_set_daemon_uds_path(
    cfg: &mut ClientConfigBuilder,
    address: *const c_char,
) {
    cfg.daemon_addr(address);
}

/// Sets the daemon's public API key.
///
/// `pk` must not be encoded; it must be the raw key bytes.
///
/// The daemon's public API key can be retrieved by invoking the
/// daemon with the `--print-api-pk` flag. The output will be
/// hexadecimal encoded and must be decoded before being passed
/// to this function. You can use [`decode_hex`] for this
/// purpose.
///
/// @param cfg a pointer to the client config builder
/// @param pk the daemon's raw (not encoded) public API key bytes
pub fn client_config_builder_set_daemon_api_pk(cfg: &mut ClientConfigBuilder, pk: &[u8]) {
    cfg.daemon_pk(pk);
}

/// Configuration info for Aranya QUIC Channels.
#[aranya_capi_core::opaque(size = 40, align = 8)]
pub type AqcConfig = Safe<imp::AqcConfig>;

/// Configuration info builder for Aranya QUIC Channels.
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 24, align = 8)]
pub type AqcConfigBuilder = Safe<imp::AqcConfigBuilder>;

/// Attempts to construct an [`AqcConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param cfg a pointer to the aqc config builder
/// @param out a pointer to write the aqc config to
pub fn aqc_config_build(
    cfg: OwnedPtr<AqcConfigBuilder>,
    out: &mut MaybeUninit<AqcConfig>,
) -> Result<(), imp::Error> {
    // SAFETY: No special considerations.
    unsafe { cfg.build(out)? }
    Ok(())
}

/// Sets the network address that the AQC server should listen
/// on.
///
/// @param cfg a pointer to the aqc config builder
/// @param address a string with the address to bind to
pub fn aqc_config_builder_set_address(cfg: &mut AqcConfigBuilder, address: *const c_char) {
    cfg.addr(address);
}

/// Sets the configuration for Aranya QUIC Channels.
///
/// @param cfg a pointer to the client config builder
/// @param aqc_config a pointer to a valid AQC config (see [`AqcConfigBuilder`])
pub fn client_config_builder_set_aqc_config(cfg: &mut ClientConfigBuilder, aqc_config: &AqcConfig) {
    cfg.aqc(aqc_config.deref().clone());
}

#[aranya_capi_core::opaque(size = 24, align = 8)]
pub type TeamConfig = Safe<imp::TeamConfig>;

#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 16, align = 8)]
pub type TeamConfigBuilder = Safe<imp::TeamConfigBuilder>;

/// Attempts to construct a [`TeamConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param cfg a pointer to the team config builder
/// @param out a pointer to write the team config to
pub fn team_config_build(
    cfg: OwnedPtr<TeamConfigBuilder>,
    out: &mut MaybeUninit<TeamConfig>,
) -> Result<(), imp::Error> {
    // SAFETY: No special considerations.
    unsafe { cfg.build(out)? }
    Ok(())
}

/// Attempts to build a [`SyncPeerConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param cfg a pointer to the builder for a sync config
pub fn sync_peer_config_build(
    cfg: OwnedPtr<SyncPeerConfigBuilder>,
    out: &mut MaybeUninit<SyncPeerConfig>,
) -> Result<(), imp::Error> {
    // SAFETY: No special considerations.
    unsafe { cfg.build(out)? }
    Ok(())
}

/// Configures how often the peer will be synced with.
///
/// By default, the interval is not set. It is an error to call
/// [`sync_peer_config_build`] before setting the interval with
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
/// @relates AranyaClient.
pub fn close_team(client: &mut Client, team: &TeamId) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.team(team.into()).close_team())?;
    Ok(())
}

/// Create a custom role.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param name role name string [`RoleName`].
///
/// Output params:
/// @param role returns the created role [`Role`].
///
/// @relates AranyaClient.
pub fn create_role(
    client: &mut Client,
    team: &TeamId,
    name: RoleName,
    role: &mut MaybeUninit<Role>,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();

    // SAFETY: Caller must ensure `name` is a valid C String.
    let name = unsafe { name.as_underlying() }?;

    let r = client
        .rt
        .block_on(client.inner.team(team.into()).create_role(name))?;
    Safe::init(role, r.clone().try_into()?);
    Ok(())
}

/// Assign permission to execute an operation to a role.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param role_id the role ID [`RoleId`] to assign an operation to.
/// @param op the operation to assign to the role [`Op`].
///
/// @relates AranyaClient.
pub fn assign_operation_to_role(
    client: &mut Client,
    team: &TeamId,
    role_id: &RoleId,
    op: Op,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();

    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .assign_operation_to_role(role_id.into(), op.into()),
    )?;
    Ok(())
}

/// Revoke role operation.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param role_id the role ID [`RoleId`] to revoke an operation from.
/// @param op the operation to revoke from the role [`Op`].
///
/// @relates AranyaClient.
pub unsafe fn revoke_role_operation(
    client: &mut Client,
    team: &TeamId,
    role_id: &RoleId,
    op: Op,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();

    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .revoke_role_operation(role_id.into(), op.into()),
    )?;
    Ok(())
}

/// Setup default roles on team.
///
/// This sets up the admin, operator, and member roles with default permissions as defined in the Aranya policy.
/// The caller should invoke this method right after team creation in order to use default RBAC from the policy.
/// If this method is not invoked, the application must manually create roles and assign permissions to them.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
///
/// @relates AranyaClient.
pub unsafe fn setup_default_roles(
    client: &mut Client,
    team: &TeamId,
    roles: Option<&mut MaybeUninit<Role>>,
    roles_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();

    let data = client
        .rt
        .block_on(client.inner.team(team.into()).setup_default_roles())?;
    let data = data.__into_data();
    let Some(roles) = roles else {
        *roles_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    };
    let len = data.len();
    if *roles_len < len {
        *roles_len = len;
        return Err(imp::Error::BufferTooSmall);
    }
    let out = aranya_capi_core::try_as_mut_slice!(roles, *roles_len);
    for (dst, src) in out.iter_mut().zip(data) {
        Safe::init(dst, src.clone().try_into()?);
    }
    *roles_len = len;
    Ok(())
}

/// Add a device to the team with the default role.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param precedence is the device's precedence [`DevicePrecedence`].
/// @param keybundle serialized keybundle byte buffer `KeyBundle`.
/// @param keybundle_len is the length of the serialized keybundle.
///
/// @relates AranyaClient.
pub unsafe fn add_device_to_team(
    client: &mut Client,
    team: &TeamId,
    precedence: &DevicePrecedence,
    keybundle: &[u8],
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let keybundle = imp::key_bundle_deserialize(keybundle)?;

    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .add_device_to_team(keybundle, precedence.0),
    )?;
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

/// By default, the peer is synced with immediately.
/// @param cfg a pointer to the builder for a sync config
// TODO: aranya-core#129
pub fn sync_peer_config_builder_set_sync_later(cfg: &mut SyncPeerConfigBuilder) {
    cfg.deref_mut().sync_now(false);
}

/// Assign device precedence.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param precedence is the device's precedence [`DevicePrecedence`].
///
/// @relates AranyaClient.
pub fn assign_device_precedence(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    precedence: &DevicePrecedence,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .assign_device_precedence(device.into(), precedence.0),
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
    role: &RoleId,
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
    role: &RoleId,
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
/// @param managing_role_id the ID of the role that is required
///        in order to grant *other* devices permission to use
///        this label.
/// Output params:
/// @param role returns the created label [`Label`].
///
/// @relates AranyaClient.
pub fn create_label(
    client: &mut Client,
    team: &TeamId,
    name: LabelName,
    managing_role_id: &RoleId,
    label: &mut MaybeUninit<Label>,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `name` is a valid C String.
    let name = unsafe { name.as_underlying() }?;
    let l = client.rt.block_on(
        client
            .inner
            .team(team.into())
            .create_label(name, managing_role_id.into()),
    )?;
    Safe::init(label, l.clone().try_into()?);
    Ok(())
}

/// Get ID of role.
///
/// @param role the role [`Role`].
///
/// Returns the role's ID [`RoleId`].
pub fn role_get_id(role: &Role) -> RoleId {
    role.id.into()
}

/// Get name of role.
///
/// @param role the role [`Role`].
///
/// Returns a C string pointer to the role's name.
#[aranya_capi_core::no_ext_error]
pub fn role_get_name(role: &Role) -> *const c_char {
    role.name.as_ptr()
}

/// Releases any resources used by the [`Role`].
///
/// @param role the role [`Role`].
pub unsafe fn role_cleanup(role: OwnedPtr<Role>) {
    // SAFETY: Caller must ensure `role` is a valid object.
    unsafe {
        role.drop_in_place();
    }
}

/// Get ID of label.
///
/// @param label the label [`Label`].
///
/// Returns the label's ID [`LabelId`].
pub fn label_get_id(label: &Label) -> LabelId {
    label.id.into()
}

/// Get name of label.
///
/// @param label the label [`Label`].
///
/// Returns a C string pointer to the label's name.
#[aranya_capi_core::no_ext_error]
pub fn label_get_name(label: &Label) -> *const c_char {
    label.name.as_ptr()
}

/// Releases any resources used by the [`Label`].
///
/// @param label the label [`Label`].
pub unsafe fn label_cleanup(label: OwnedPtr<Label>) {
    // SAFETY: Caller must ensure `label` is a valid object.
    unsafe {
        label.drop_in_place();
    }
}

/// Writes `Op` to `str`.
///
/// To always succeed, `str` must be large enough to contain the operation string.
///
/// @param op the operation [`Op`].
/// @param str Op string [`Id`].
/// @param str_len returns the length of `str`
///
/// @relates AranyaId.
#[aranya_capi_core::no_ext_error]
pub fn op_to_str(
    op: Op,
    str: &mut MaybeUninit<c_char>,
    str_len: &mut usize,
) -> Result<(), imp::Error> {
    let str = aranya_capi_core::try_as_mut_slice!(str, *str_len);
    let op: aranya_client::Op = op.into();
    aranya_capi_core::write_c_str(str, &op.to_string(), str_len)?;
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
            .add_sync_peer(addr, (*config).clone().into()),
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
            .sync_now(addr, config.map(|config| (*config).clone().into())),
    )?;
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
    labels: Option<&mut MaybeUninit<Label>>,
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
        Safe::init(dst, src.clone().try_into()?)
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
    labels: Option<&mut MaybeUninit<Label>>,
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
        Safe::init(dst, src.clone().try_into()?);
    }
    if *labels_len < data.len() {
        *labels_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    }
    *labels_len = data.len();
    Ok(())
}

/// Query for list of roles on team.
///
/// Returns an `AranyaBufferTooSmall` error if the output buffer is too small to hold the roles.
/// Writes the number of roles that would have been returned to `roles_len`.
/// The application can use `roles_len` to allocate a larger buffer.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
///
/// Output params:
/// @param roles returns a list of roles [`Role`].
/// @param roles_len returns the length of the roles list [`Role`].
///
/// @relates AranyaClient.
pub fn query_roles_on_team(
    client: &mut Client,
    team: &TeamId,
    roles: Option<&mut MaybeUninit<Role>>,
    roles_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let data = client
        .rt
        .block_on(client.inner.queries(team.into()).roles_on_team())?;
    let data = data.__into_data();
    let Some(roles) = roles else {
        *roles_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    };
    let len = data.len();
    if *roles_len < len {
        *roles_len = len;
        return Err(imp::Error::BufferTooSmall);
    }
    let out = aranya_capi_core::try_as_mut_slice!(roles, *roles_len);
    for (dst, src) in out.iter_mut().zip(data) {
        Safe::init(dst, src.try_into()?);
    }
    *roles_len = len;
    Ok(())
}

/// Query for list of roles assigned to a device.
///
/// Returns an `AranyaBufferTooSmall` error if the output buffer is too small to hold the roles.
/// Writes the number of roles that would have been returned to `roles_len`.
/// The application can use `roles_len` to allocate a larger buffer.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
///
/// Output params:
/// @param roles returns a list of roles [`RoleId`].
/// @param roles_len returns the length of the roles list [`RoleId`].
///
/// @relates AranyaClient.
pub fn query_device_roles(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    roles: Option<&mut MaybeUninit<Role>>,
    roles_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let data = client.rt.block_on(
        client
            .inner
            .queries(team.into())
            .device_roles(device.into()),
    )?;
    let data = data.__into_data();
    let Some(roles) = roles else {
        *roles_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    };
    let len = data.len();
    if *roles_len < len {
        *roles_len = len;
        return Err(imp::Error::BufferTooSmall);
    }
    let out = aranya_capi_core::try_as_mut_slice!(roles, *roles_len);
    for (dst, src) in out.iter_mut().zip(data) {
        Safe::init(dst, src.try_into()?);
    }
    *roles_len = len;
    Ok(())
}

/// Query for list of operations assigned to the role.
///
/// Returns an `AranyaBufferTooSmall` error if the output buffer is too small to hold the operations.
/// Writes the number of roles that would have been returned to `op_len`.
/// The application can use `op_len` to allocate a larger buffer.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param role the role's ID [`RoleId`].
///
/// Output params:
/// @param ops returns a list of operations [`Op`].
/// @param ops_len returns the length of the operations list [`RoleId`].
///
/// @relates AranyaClient.
pub fn query_role_operations(
    client: &mut Client,
    team: &TeamId,
    role: &RoleId,
    ops: Option<&mut MaybeUninit<AranyaOp>>,
    ops_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    let data = client
        .rt
        .block_on(client.inner.queries(team.into()).role_ops(role.into()))?;
    let data = data.__into_data();
    let Some(ops) = ops else {
        *ops_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    };
    let len = data.len();
    if *ops_len < len {
        *ops_len = len;
        return Err(imp::Error::BufferTooSmall);
    }
    let out = aranya_capi_core::try_as_mut_slice!(ops, *ops_len);
    for (dst, src) in out.iter_mut().zip(data) {
        dst.write(src.into());
    }
    *ops_len = len;
    Ok(())
}

/// Create an AQC channel.
///
/// Creates a bidirectional AQC channel between the current device
/// and another peer.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param peer the peer's network identifier [`NetIdentifier`].
/// @param label_id the AQC channel label ID [`LabelId`] to create the channel with.
/// @param __output the AQC channel's ID [`AqcBidiChannelId`]
///
/// @relates AranyaClient.
pub unsafe fn aqc_create_bidi_channel(
    client: &mut Client,
    team: &TeamId,
    peer: NetIdentifier,
    label_id: &LabelId,
) -> Result<AqcBidiChannelId, imp::Error> {
    let client = client.deref_mut();
    let chan_id = client.rt.block_on(client.inner.aqc().create_bidi_channel(
        team.into(),
        peer,
        label_id.into(),
    ))?;
    Ok(chan_id.into())
}

/// Delete a bidirectional AQC channel.
///
/// @param client the Aranya Client [`Client`].
/// @param chan the AQC channel ID [`AqcBidiChannelId`] of the channel to delete.
///
/// @relates AranyaClient.
pub fn aqc_delete_bidi_channel(
    client: &mut Client,
    chan: &AqcBidiChannelId,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.aqc().delete_bidi_channel(chan.into()))?;
    Ok(())
}

/// Delete a unidirectional AQC channel.
///
/// @param client the Aranya Client [`Client`].
/// @param chan the AQC channel ID [`AqcUniChannelId`] of the channel to delete.
///
/// @relates AranyaClient.
pub fn aqc_delete_uni_channel(
    client: &mut Client,
    chan: &AqcUniChannelId,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.aqc().delete_uni_channel(chan.into()))?;
    Ok(())
}
