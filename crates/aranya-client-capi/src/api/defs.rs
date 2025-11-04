#![allow(rustdoc::broken_intra_doc_links)]
use core::{
    ffi::{c_char, CStr},
    ops::Deref,
    ptr, slice,
};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use anyhow::Context as _;
use aranya_capi_core::{prelude::*, ErrorCode, InvalidArg};
#[cfg(feature = "afc")]
use aranya_client::afc;
use aranya_daemon_api::Text;
use aranya_util::error::ReportExt as _;
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

    /// Invalid argument.
    #[capi(msg = "invalid argument")]
    InvalidArgument,

    /// Component is not enabled.
    #[capi(msg = "component not enabled")]
    NotEnabled,

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

    #[cfg(feature = "afc")]
    #[capi(msg = "wrong channel type provided")]
    WrongChannelType,

    /// Tried to poll an endpoint but nothing received yet.
    #[capi(msg = "no response ready yet")]
    WouldBlock,

    /// A connection got unexpectedly closed.
    #[capi(msg = "connection got closed")]
    Closed,

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
        debug!(error = %err.report(), "Aranya client C API error");
        match err {
            imp::Error::Bug(_) => Self::Bug,
            imp::Error::Timeout(_) => Self::Timeout,
            imp::Error::InvalidArg(_) => Self::InvalidArgument,
            imp::Error::NotEnabled => Self::NotEnabled,
            imp::Error::Utf8(_) => Self::InvalidUtf8,
            imp::Error::Addr(_) => Self::InvalidAddr,
            imp::Error::BufferTooSmall => Self::BufferTooSmall,
            imp::Error::Client(err) => match err {
                aranya_client::Error::Ipc(_) => Self::Ipc,
                aranya_client::Error::Aranya(_) => Self::Aranya,
                aranya_client::Error::Bug(_) => Self::Bug,
                aranya_client::Error::Config(_) => Self::Config,
                aranya_client::Error::Other(_) => Self::Other,
                _ => {
                    error!("forgot to implement an error variant");
                    Self::Bug
                }
            },
            #[cfg(feature = "afc")]
            imp::Error::WrongChannelType => Self::WrongChannelType,
            imp::Error::WouldBlock => Self::WouldBlock,
            imp::Error::Closed => Self::Closed,
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
/// @param[in] err `u32` error code from `AranyaError`.
///
/// @relates AranyaError.
#[aranya_capi_core::no_ext_error]
pub fn error_to_str(err: u32) -> *const c_char {
    match Error::try_from_repr(err) {
        Some(v) => v.to_cstr().as_ptr(),
        None => c"invalid error code".as_ptr(),
    }
}

/// * ─────────────────────── Extended‐error (_ext) Variants ───────────────────────
/// *
/// * Functions suffixed with `_ext` accept an extra
/// * `struct AranyaExtError *ext_err` parameter for extended error information.
/// *
/// * - `ext_err` must be a valid, non-NULL pointer.
/// * - If the call returns anything other than `ARANYA_ERROR_SUCCESS`,
/// *   `*ext_err` is populated with additional error details.
/// * - On success, the content of `ext_err` is unchanged.
/// * - To extract a human-readable message:
/// *
/// *       AranyaError aranya_ext_error_msg(
/// *           const struct AranyaExtError *err,
/// *           char *msg,
/// *           size_t *msg_len
/// *       );
/// *
/// * Example:
/// *     struct AranyaExtError ext_err;
/// *     AranyaError rc = aranya_get_device_id_ext(client, &id, &ext_err);
/// *     if (rc != ARANYA_ERROR_SUCCESS) {
/// *         size_t len = 0;
/// *         aranya_ext_error_msg(&ext_err, NULL, &len);
/// *         char *buf = malloc(len);
/// *         aranya_ext_error_msg(&ext_err, buf, &len);
/// *         // `buf` now holds the detailed error message
/// *     }
/// * ──────────────────────────────────────────────────────────────────────────────
/// Extended error information.
#[allow(rustdoc::invalid_rust_codeblocks)]
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 96, align = 8)]
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
/// @param[in] err the error to get a message for [`ExtError`].
/// @param[out] msg buffer to copy error message into.
/// @param[in,out] msg_len length of the message buffer.
///
/// @relates AranyaExtError.
pub unsafe fn ext_error_msg(
    err: &ExtError,
    msg: *mut MaybeUninit<c_char>,
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
/// @param[out] client the uninitialized Aranya Client [`Client`].
/// @param[in] config the client's configuration [`ClientConfig`].
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
            .connect()
    })?;

    Client::init(client, imp::Client { rt, inner });
    Ok(())
}

/// A handle to an Aranya Client.
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 3728, align = 16)]
pub type Client = Safe<imp::Client>;

/// The size in bytes of an ID
pub const ARANYA_ID_LEN: usize = 32;

const _: () = {
    assert!(ARANYA_ID_LEN == size_of::<aranya_id::BaseId>());
};

/// Cryptographically secure Aranya ID.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Id {
    bytes: [u8; ARANYA_ID_LEN],
}

impl AsRef<aranya_id::BaseId> for Id {
    fn as_ref(&self) -> &aranya_id::BaseId {
        // SAFETY: Each type is a struct with a single field containing an array of 64 bytes
        unsafe { &*ptr::from_ref::<[u8; ARANYA_ID_LEN]>(&self.bytes).cast::<aranya_id::BaseId>() }
    }
}

impl From<aranya_id::BaseId> for Id {
    fn from(value: aranya_id::BaseId) -> Self {
        Id {
            bytes: value.into(),
        }
    }
}

/// The size in bytes of a PSK seed IKM.
pub const ARANYA_SEED_IKM_LEN: usize = 32;

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
#[derive(Copy, Clone, Debug)]
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

/// A role.
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 112, align = 8)]
pub type Role = Safe<imp::Role>;

/// Uniquely identifies a [`Role`].
#[repr(C)]
#[derive(Copy, Clone, Debug)]
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

/// Get ID of role.
///
/// @param[in] role the role [`Role`].
///
/// @relates AranyaRole
pub fn role_get_id(role: &Role) -> RoleId {
    role.deref().id.into()
}

/// Get name of role.
///
/// The resulting string must not be freed.
///
/// @param[in] role the role [`Role`].
///
/// @relates AranyaRole
#[aranya_capi_core::no_ext_error]
pub fn role_get_name(role: &Role) -> *const c_char {
    role.deref().name.as_ptr().cast()
}

/// Get the author of a role.
///
/// @param[in] role the role [`Role`].
///
/// @relates AranyaRole
pub fn role_get_author(role: &Role) -> DeviceId {
    role.deref().author_id.into()
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
    /// The device can send or receive data in channels with this
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

/// A label name.
///
/// E.g. "TELEMETRY_LABEL"
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct LabelName(*const c_char);

impl LabelName {
    unsafe fn as_underlying(self) -> Result<Text, imp::Error> {
        // SAFETY: Caller must ensure the pointer is a valid C String.
        let cstr = unsafe { CStr::from_ptr(self.0) };
        Ok(Text::try_from(cstr)?)
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

/// The name of a permission.
///
/// E.g. "CanAssignRole"
///
/// Refer to the "Role Management" section of the policy for an exhaustive list.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct Permission(*const c_char);

impl Permission {
    unsafe fn as_underlying(self) -> Result<Text, imp::Error> {
        // SAFETY: Caller must ensure the pointer is a valid C String.
        let cstr = unsafe { CStr::from_ptr(self.0) };
        Ok(Text::try_from(cstr)?)
    }
}

/// Channel ID for AFC channel.
#[cfg(feature = "afc")]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AfcChannelId {
    id: Id,
}

#[cfg(feature = "afc")]
impl From<afc::ChannelId> for AfcChannelId {
    fn from(value: afc::ChannelId) -> Self {
        Self {
            id: Id {
                bytes: value.__id.into(),
            },
        }
    }
}

#[cfg(feature = "afc")]
impl From<&AfcChannelId> for afc::ChannelId {
    fn from(value: &AfcChannelId) -> Self {
        Self {
            __id: aranya_daemon_api::AfcChannelId::from_bytes(value.id.bytes),
        }
    }
}

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

/// Gets the public key bundle for this device.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[out] keybundle keybundle byte buffer `KeyBundle`.
/// @param[in,out] keybundle_len returns the length of the serialized keybundle.
///
/// @relates AranyaClient.
pub unsafe fn get_key_bundle(
    client: &Client,
    keybundle: *mut MaybeUninit<u8>,
    keybundle_len: &mut usize,
) -> Result<(), imp::Error> {
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
/// @param[in] device ID [`Id`].
/// @param[out] str ID string [`Id`].
/// @param[in,out] str_len returns the length of `str`
///
/// @relates AranyaId.
#[aranya_capi_core::no_ext_error]
pub unsafe fn id_to_str(
    id: &Id,
    str: *mut MaybeUninit<c_char>,
    str_len: &mut usize,
) -> Result<(), imp::Error> {
    let str = aranya_capi_core::try_as_mut_slice!(str, *str_len);
    aranya_capi_core::write_c_str(str, id.as_ref(), str_len)?;
    Ok(())
}

/// Decodes `str` into an [`Id`].
///
/// @param[in] str pointer to a null-terminated string.
///
/// @relates AranyaId.
#[aranya_capi_core::no_ext_error]
pub unsafe fn id_from_str(str: *const c_char) -> Result<Id, imp::Error> {
    // SAFETY: Caller must ensure the pointer is a valid C String.
    let cstr = unsafe { CStr::from_ptr(str) };

    aranya_id::BaseId::decode(cstr.to_bytes())
        .map_err(|_| InvalidArg::new("str", "unable to decode ID from bytes").into())
        .map(Into::into)
}

/// Gets the public device ID.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[out] __output the client's device ID [`DeviceId`].
///
/// @relates AranyaClient.
pub fn get_device_id(client: &Client) -> Result<DeviceId, imp::Error> {
    let id = client.rt.block_on(client.inner.get_device_id())?;
    Ok(id.into())
}

/// Configuration info for Aranya.
///
/// Use a [`ClientConfigBuilder`] to construct this object.
#[aranya_capi_core::opaque(size = 56, align = 8)]
pub type ClientConfig = Safe<imp::ClientConfig>;

/// Configuration info builder for an Aranya client config [`ClientConfig`].
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 72, align = 8)]
pub type ClientConfigBuilder = Safe<imp::ClientConfigBuilder>;

/// Attempts to construct a [`ClientConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param[in] cfg a pointer to the client config builder
/// @param[out] out a pointer to write the client config to
///
/// @relates AranyaClientConfigBuilder.
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
/// @param[in,out] cfg a pointer to the client config builder
/// @param[in] address a string containing the address
///
/// @relates AranyaClientConfigBuilder.
pub fn client_config_builder_set_daemon_uds_path(
    cfg: &mut ClientConfigBuilder,
    address: *const c_char,
) {
    cfg.daemon_addr(address);
}

/// QUIC syncer configuration.
///
/// Use a [`CreateTeamQuicSyncConfigBuilder`] to construct this object.
#[aranya_capi_core::opaque(size = 56, align = 8)]
pub type CreateTeamQuicSyncConfig = Safe<imp::CreateTeamQuicSyncConfig>;

/// QUIC syncer configuration.
///
/// Use an [`AddTeamQuicSyncConfigBuilder`] to construct this object.
#[aranya_capi_core::opaque(size = 288, align = 8)]
pub type AddTeamQuicSyncConfig = Safe<imp::AddTeamQuicSyncConfig>;

/// A builder for initializing an [`AddTeamQuicSyncConfig`].
///
/// The [`AddTeamQuicSyncConfig`] is an optional part of initializing an [`AddTeamConfig`].
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 288, align = 8)]
pub type AddTeamQuicSyncConfigBuilder = Safe<imp::AddTeamQuicSyncConfigBuilder>;

/// A builder for initializing a [`CreateTeamQuicSyncConfig`].
///
/// The [`CreateTeamQuicSyncConfig`] is an optional part of initializing a [`CreateTeamConfig`].
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 56, align = 8)]
pub type CreateTeamQuicSyncConfigBuilder = Safe<imp::CreateTeamQuicSyncConfigBuilder>;

/// Attempts to set PSK seed generation mode value on [`CreateTeamQuicSyncConfigBuilder`].
///
/// @param[in,out] cfg a pointer to the quic sync config builder
///
/// This method will be removed soon since certificates will be used instead of PSKs in the future.
///
/// @relates AranyaCreateTeamQuicSyncConfigBuilder.
pub fn create_team_quic_sync_config_generate(
    cfg: &mut CreateTeamQuicSyncConfigBuilder,
) -> Result<(), imp::Error> {
    cfg.generate();
    Ok(())
}

/// Attempts to set wrapped PSK seed value on [`AddTeamQuicSyncConfigBuilder`].
///
/// @param[in,out] cfg a pointer to the quic sync config builder
/// @param[in] encap_seed a pointer the encapsulated PSK seed
///
/// This method will be removed soon since certificates will be used instead of PSKs in the future.
///
/// @relates AranyaAddTeamQuicSyncConfigBuilder.
pub fn add_team_quic_sync_config_wrapped_seed(
    cfg: &mut AddTeamQuicSyncConfigBuilder,
    encap_seed: &[u8],
) -> Result<(), imp::Error> {
    cfg.wrapped_seed(encap_seed)?;
    Ok(())
}

/// Raw PSK seed IKM for QUIC syncer.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SeedIkm {
    bytes: [u8; ARANYA_SEED_IKM_LEN],
}

/// Attempts to set raw PSK seed IKM value [`SeedIkm`] on [`CreateTeamQuicSyncConfigBuilder`].
///
/// @param[in,out] cfg a pointer to the quic sync config builder [`CreateTeamQuicSyncConfigBuilder`]
/// @param[in] ikm a pointer the raw PSK seed IKM [`SeedIkm`]
///
/// This method will be removed soon since certificates will be used instead of PSKs in the future.
///
/// @relates AranyaCreateTeamQuicSyncConfigBuilder.
pub fn create_team_quic_sync_config_raw_seed_ikm(
    cfg: &mut CreateTeamQuicSyncConfigBuilder,
    ikm: &SeedIkm,
) -> Result<(), imp::Error> {
    cfg.raw_seed_ikm(ikm.bytes);
    Ok(())
}

/// Attempts to set raw PSK seed IKM value [`SeedIkm`] on [`AddTeamQuicSyncConfigBuilder`].
///
/// @param[in,out] cfg a pointer to the quic sync config builder [`AddTeamQuicSyncConfigBuilder`]
/// @param[in] ikm a pointer the raw PSK seed IKM [`SeedIkm`]
///
/// This method will be removed soon since certificates will be used instead of PSKs in the future.
///
/// @relates AranyaAddTeamQuicSyncConfigBuilder.
pub fn add_team_quic_sync_config_raw_seed_ikm(
    cfg: &mut AddTeamQuicSyncConfigBuilder,
    ikm: &SeedIkm,
) -> Result<(), imp::Error> {
    cfg.raw_seed_ikm(ikm.bytes);
    Ok(())
}

/// Attempts to construct a [`CreateTeamQuicSyncConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param[in] cfg a pointer to the QUIC sync config builder [`CreateTeamQuicSyncConfigBuilder`]
/// @param[out] out a pointer to write the QUIC sync config to [`CreateTeamQuicSyncConfig`]
///
/// @relates AranyaCreateTeamQuicSyncConfigBuilder.
pub fn create_team_quic_sync_config_build(
    cfg: OwnedPtr<CreateTeamQuicSyncConfigBuilder>,
    out: &mut MaybeUninit<CreateTeamQuicSyncConfig>,
) -> Result<(), imp::Error> {
    // SAFETY: No special considerations.
    unsafe { cfg.build(out)? }
    Ok(())
}

/// Attempts to construct an [`AddTeamQuicSyncConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param[in] cfg a pointer to the QUIC sync config builder [`AddTeamQuicSyncConfigBuilder`]
/// @param[out] out a pointer to write the QUIC sync config to [`AddTeamQuicSyncConfig`]
///
/// @relates AranyaAddTeamQuicSyncConfigBuilder.
pub fn add_team_quic_sync_config_build(
    cfg: OwnedPtr<AddTeamQuicSyncConfigBuilder>,
    out: &mut MaybeUninit<AddTeamQuicSyncConfig>,
) -> Result<(), imp::Error> {
    // SAFETY: No special considerations.
    unsafe { cfg.build(out)? }
    Ok(())
}

/// Team configuration used when joining a team.
///
/// Use an [`AddTeamConfigBuilder`] to construct this object.
#[aranya_capi_core::opaque(size = 320, align = 8)]
pub type AddTeamConfig = Safe<imp::AddTeamConfig>;

/// A builder for initializing an [`AddTeamConfig`].
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 328, align = 8)]
pub type AddTeamConfigBuilder = Safe<imp::AddTeamConfigBuilder>;

/// Team configuration used when creating a team.
///
/// Use a [`CreateTeamConfigBuilder`] to construct this object.
#[aranya_capi_core::opaque(size = 56, align = 8)]
pub type CreateTeamConfig = Safe<imp::CreateTeamConfig>;

/// A builder for initializing a [`CreateTeamConfig`].
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 56, align = 8)]
pub type CreateTeamConfigBuilder = Safe<imp::CreateTeamConfigBuilder>;

/// Configures QUIC syncer for [`AddTeamConfigBuilder`].
///
/// By default, the QUIC syncer config is not set.
///
/// @param[in,out] cfg a pointer to the builder for a team config [`AddTeamConfigBuilder`]
/// @param[in] quic set the QUIC syncer config [`AddTeamQuicSyncConfig`]
///
/// @relates AranyaAddTeamConfigBuilder.
pub fn add_team_config_builder_set_quic_syncer(
    cfg: &mut AddTeamConfigBuilder,
    quic: OwnedPtr<AddTeamQuicSyncConfig>,
) {
    // SAFETY: the user is responsible for passing in a valid AddTeamQuicSyncConfig pointer.
    let quic = unsafe { quic.read() };
    cfg.quic(quic.imp());
}

/// Configures team ID field for [`AddTeamConfigBuilder`].
///
/// By default, the team ID is not set.
///
/// @param[in,out] cfg a pointer to the builder for a team config [`AddTeamConfigBuilder`]
/// @param[in] id a pointer to a [`TeamId`]
///
/// @relates AranyaAddTeamConfigBuilder.
pub fn add_team_config_builder_set_id(cfg: &mut AddTeamConfigBuilder, team_id: &TeamId) {
    cfg.id(*team_id);
}

/// Attempts to construct an [`AddTeamConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param[in] cfg a pointer to the team config builder [`AddTeamConfigBuilder`]
/// @param[out] out a pointer to write the team config to [`AddTeamConfig`]
///
/// @relates AranyaAddTeamConfigBuilder.
pub fn add_team_config_build(
    cfg: OwnedPtr<AddTeamConfigBuilder>,
    out: &mut MaybeUninit<AddTeamConfig>,
) -> Result<(), imp::Error> {
    // SAFETY: No special considerations.
    unsafe { cfg.build(out)? }
    Ok(())
}

/// Configures QUIC syncer for [`CreateTeamConfigBuilder`].
///
/// By default, the QUIC syncer config is not set.
///
/// @param[in,out] cfg a pointer to the builder for a team config [`CreateTeamConfigBuilder`]
/// @param[in] quic set the QUIC syncer config [`CreateTeamQuicSyncConfig`]
///
/// @relates AranyaCreateTeamConfigBuilder.
pub fn create_team_config_builder_set_quic_syncer(
    cfg: &mut CreateTeamConfigBuilder,
    quic: OwnedPtr<CreateTeamQuicSyncConfig>,
) {
    // SAFETY: the user is responsible for passing in a valid CreateTeamQuicSyncConfig pointer.
    let quic = unsafe { quic.read() };
    cfg.quic(quic.imp());
}

/// Attempts to construct a [`CreateTeamConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param[in] cfg a pointer to the team config builder [`CreateTeamConfigBuilder`]
/// @param[out] out a pointer to write the team config to [`CreateTeamConfig`]
///
/// @relates AranyaCreateTeamConfigBuilder.
pub fn create_team_config_build(
    cfg: OwnedPtr<CreateTeamConfigBuilder>,
    out: &mut MaybeUninit<CreateTeamConfig>,
) -> Result<(), imp::Error> {
    // SAFETY: No special considerations.
    unsafe { cfg.build(out)? }
    Ok(())
}

/// Sync Peer config.
///
/// Use a [`SyncPeerConfigBuilder`] to construct this object.
#[aranya_capi_core::opaque(size = 32, align = 8)]
pub type SyncPeerConfig = Safe<imp::SyncPeerConfig>;

/// Builder for a Sync Peer config [`SyncPeerConfig`].
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 40, align = 8)]
pub type SyncPeerConfigBuilder = Safe<imp::SyncPeerConfigBuilder>;

/// Attempts to build a [`SyncPeerConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param[in] cfg a pointer to the builder for a sync config [`SyncPeerConfigBuilder`]
/// @param[out] out a pointer to write the sync config to [`SyncPeerConfig`]
///
/// @relates AranyaSyncPeerConfigBuilder.
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
/// @param[in,out] cfg a pointer to the builder for a sync config
/// @param[in] interval Set the interval at which syncing occurs
///
/// @relates AranyaSyncPeerConfigBuilder.
pub fn sync_peer_config_builder_set_interval(cfg: &mut SyncPeerConfigBuilder, interval: Duration) {
    cfg.interval(interval);
}

/// Updates the config to enable immediate syncing with the peer.
///
/// Overrides [`sync_peer_config_builder_set_sync_later`] if invoked afterward.
///
/// By default, the peer is synced with immediately.
///
/// @param[in,out] cfg a pointer to the builder for a sync config
///
/// @relates AranyaSyncPeerConfigBuilder.
// TODO: aranya-core#129
pub fn sync_peer_config_builder_set_sync_now(cfg: &mut SyncPeerConfigBuilder) {
    cfg.sync_now(true);
}

/// Updates the config to disable immediate syncing with the peer.
///
/// Overrides [`sync_peer_config_builder_set_sync_now`] if invoked afterward.
///
/// By default, the peer is synced with immediately.
/// @param[in,out] cfg a pointer to the builder for a sync config
///
/// @relates AranyaSyncPeerConfigBuilder.
// TODO: aranya-core#129
pub fn sync_peer_config_builder_set_sync_later(cfg: &mut SyncPeerConfigBuilder) {
    cfg.sync_now(false);
}

/// Setup default roles on team.
///
/// This sets up the following roles with default permissions as
/// defined in Aranya's default policy:
/// - admin
/// - operator
/// - member
///
/// Returns an `AranyaBufferTooSmall` error if the output buffer is too small to hold the roles.
/// Writes the number of roles that would have been returned to `roles_len`.
/// The application can use `roles_len` to allocate a larger buffer.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] roles_out returns a list of roles that own `role` [`Role`].
/// @param[in,out] roles_len the number of roles written to the buffer.
///
/// @relates AranyaClient.
pub unsafe fn setup_default_roles(
    client: &mut Client,
    team: &TeamId,
    roles_out: *mut MaybeUninit<Role>,
    roles_len: &mut usize,
) -> Result<(), imp::Error> {
    // First get the owner role ID by looking at existing roles
    let roles = client.rt.block_on(client.inner.team(team.into()).roles())?;

    let owner_role = roles
        .into_iter()
        .find(|role| role.name == "owner" && role.default)
        .ok_or_else(|| {
            imp::Error::InvalidArg(InvalidArg::new(
                "setup_default_roles",
                "owner role not found",
            ))
        })?;

    let default_roles = client
        .rt
        .block_on(
            client
                .inner
                .team(team.into())
                .setup_default_roles(owner_role.id),
        )?
        .__into_data();

    if *roles_len < default_roles.len() {
        *roles_len = default_roles.len();
        return Err(imp::Error::BufferTooSmall);
    }
    *roles_len = default_roles.len();
    let out = aranya_capi_core::try_as_mut_slice!(roles_out, *roles_len);

    for (dst, src) in out.iter_mut().zip(default_roles) {
        Role::init(dst, imp::Role(src));
    }

    Ok(())
}

/// Adds `owning_role` as an owner of role.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] role ID of the subject role [`RoleId`].
/// @param[in] owning_role ID of the owning role [`RoleId`].
///
/// @relates AranyaClient.
pub fn add_role_owner(
    client: &Client,
    team: &TeamId,
    role: &RoleId,
    owning_role: &RoleId,
) -> Result<(), imp::Error> {
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .add_role_owner(role.into(), owning_role.into()),
    )?;

    Ok(())
}

/// Removes an owning_role as an owner of role.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] role the ID of the subject role [`RoleId`].
/// @param[in] owning_role ID of the owning role [`RoleId`].
///
/// @relates AranyaClient.
pub fn remove_role_owner(
    client: &Client,
    team: &TeamId,
    role: &RoleId,
    owning_role: &RoleId,
) -> Result<(), imp::Error> {
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .remove_role_owner(role.into(), owning_role.into()),
    )?;

    Ok(())
}

/// Returns the roles that own `role`.
///
/// Returns an `AranyaBufferTooSmall` error if the output buffer is too small to hold the roles.
/// Writes the number of roles that would have been returned to `roles_len`.
/// The application can use `roles_len` to allocate a larger buffer.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] role the ID of the subject role [`RoleId`].
/// @param[in] roles_out returns a list of roles that own `role` [`Role`].
/// @param[in,out] roles_len the number of roles written to the buffer.
///
/// @relates AranyaClient.
pub unsafe fn role_owners(
    client: &Client,
    team: &TeamId,
    role: &RoleId,
    roles_out: *mut MaybeUninit<Role>,
    roles_len: &mut usize,
) -> Result<(), imp::Error> {
    let owning_roles = client
        .rt
        .block_on(client.inner.team(team.into()).role_owners(role.into()))?
        .__into_data();

    if *roles_len < owning_roles.len() {
        *roles_len = owning_roles.len();
        return Err(imp::Error::BufferTooSmall);
    }
    *roles_len = owning_roles.len();
    let out = aranya_capi_core::try_as_mut_slice!(roles_out, *roles_len);

    for (dst, src) in out.iter_mut().zip(owning_roles) {
        Role::init(dst, imp::Role(src));
    }

    Ok(())
}

/// Assigns a role management permission to a managing role.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] role the ID of the subject role [`RoleId`].
/// @param[in] managing_role the ID of the managing role [`RoleId`].
/// @param[in] perm the management permission to assign [`Permission`].
///
/// @relates AranyaClient.
pub fn assign_role_management_permission(
    client: &Client,
    team: &TeamId,
    role: &RoleId,
    managing_role: &RoleId,
    perm: Permission,
) -> Result<(), imp::Error> {
    // SAFETY: Caller must ensure `perm` is a valid C String.
    let perm = unsafe { perm.as_underlying() }?;

    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .assign_role_management_permission(role.into(), managing_role.into(), perm),
    )?;

    Ok(())
}

/// Revokes a role management permission from a managing role.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] role the ID of the subject role [`RoleId`].
/// @param[in] managing_role the ID of the managing role [`RoleId`].
/// @param[in] perm the management permission to assign [`Permission`].
///
/// @relates AranyaClient.
pub fn revoke_role_management_permission(
    client: &Client,
    team: &TeamId,
    role: &RoleId,
    managing_role: &RoleId,
    perm: Permission,
) -> Result<(), imp::Error> {
    // SAFETY: Caller must ensure `perm` is a valid C String.
    let perm = unsafe { perm.as_underlying() }?;

    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .revoke_role_management_permission(role.into(), managing_role.into(), perm),
    )?;

    Ok(())
}

/// Changes the `role` on a `device`
///
/// This will change the device's current role to the new role assigned.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[in] old_role the ID of the role currently assigned to the device [`RoleId`].
/// @param[in] new_role the ID of the role to assign to the device [`RoleId`].
///
/// @relates AranyaClient.
pub fn change_role(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    old_role: &RoleId,
    new_role: &RoleId,
) -> Result<(), imp::Error> {
    client
        .rt
        .block_on(client.inner.team(team.into()).change_role(
            device.into(),
            old_role.into(),
            new_role.into(),
        ))?;

    Ok(())
}

/// Returns all of the roles for this team.
///
/// Returns an `AranyaBufferTooSmall` error if the output buffer is too small to hold the roles.
/// Writes the number of roles that would have been returned to `roles_len`.
/// The application can use `roles_len` to allocate a larger buffer.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[out] roles_out returns a list of roles on the team [`Role`].
/// @param[in,out] roles_len the number of roles written to the buffer.
///
/// @relates AranyaClient.
pub unsafe fn team_roles(
    client: &Client,
    team: &TeamId,
    roles_out: *mut MaybeUninit<Role>,
    roles_out_len: &mut usize,
) -> Result<(), imp::Error> {
    let roles = client
        .rt
        .block_on(client.inner.team(team.into()).roles())?
        .__into_data();

    if *roles_out_len < roles.len() {
        *roles_out_len = roles.len();
        return Err(imp::Error::BufferTooSmall);
    }
    *roles_out_len = roles.len();
    let out = aranya_capi_core::try_as_mut_slice!(roles_out, *roles_out_len);

    for (dst, src) in out.iter_mut().zip(roles) {
        Role::init(dst, imp::Role(src));
    }

    Ok(())
}

/// Assign a role to a device.
///
/// This will change the device's currently assigned role to the new role.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// It is an error if the device has already been assigned a role.
/// If you want to assign a different role to a device that already
/// has a role, use `change_role()` instead.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[in] role_id the ID of the role to assign to the device [`RoleId`].
///
/// @relates AranyaClient.
pub fn assign_role(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    role_id: &RoleId,
) -> Result<(), imp::Error> {
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .assign_role(device.into(), role_id.into()),
    )?;
    Ok(())
}

/// Revoke a role from a device.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[in] role_id the ID of the role to revoke from the device.
///
/// @relates AranyaClient.
pub fn revoke_role(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    role_id: &RoleId,
) -> Result<(), imp::Error> {
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .revoke_role(device.into(), role_id.into()),
    )?;
    Ok(())
}

/// Create a channel label.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] name label name string [`LabelName`].
/// @param[in] managing_role_id the ID of the role that manages this
///        label [`RoleId`].
///
/// @relates AranyaClient.
pub fn create_label(
    client: &Client,
    team: &TeamId,
    name: LabelName,
    managing_role_id: &RoleId,
) -> Result<LabelId, imp::Error> {
    // SAFETY: Caller must ensure `name` is a valid C String.
    let name = unsafe { name.as_underlying() }?;
    let label_id = client.rt.block_on(
        client
            .inner
            .team(team.into())
            .create_label(name, managing_role_id.into()),
    )?;
    Ok(label_id.into())
}

/// Delete a channel label.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] label_id the channel label ID [`LabelId`] to delete.
///
/// @relates AranyaClient.
pub fn delete_label(client: &Client, team: &TeamId, label_id: &LabelId) -> Result<(), imp::Error> {
    client
        .rt
        .block_on(client.inner.team(team.into()).delete_label(label_id.into()))?;
    Ok(())
}

/// Assign a label to a device so that it can be used for a channel.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device ID [`DeviceId`] of the device to assign the label to.
/// @param[in] label_id the channel label ID [`LabelId`].
///
/// @relates AranyaClient.
pub fn assign_label(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    label_id: &LabelId,
    op: ChanOp,
) -> Result<(), imp::Error> {
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .device(device.into())
            .assign_label(label_id.into(), op.into()),
    )?;
    Ok(())
}

/// Revoke a label from a device.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device ID [`DeviceId`] of the device to revoke the label from.
/// @param[in] label_id the channel label ID [`LabelId`].
///
/// @relates AranyaClient.
pub fn revoke_label(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    label_id: &LabelId,
) -> Result<(), imp::Error> {
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .device(device.into())
            .revoke_label(label_id.into()),
    )?;
    Ok(())
}

/// Create a new graph/team with the current device as the owner.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] cfg the Team Configuration [`CreateTeamConfig`].
/// @param[out] __output the team's ID [`TeamId`].
///
/// @relates AranyaClient.
pub fn create_team(client: &Client, cfg: &CreateTeamConfig) -> Result<TeamId, imp::Error> {
    let cfg: &imp::CreateTeamConfig = cfg.deref();
    let team_id = client
        .rt
        .block_on(client.inner.create_team(cfg.into()))?
        .team_id();

    Ok(team_id.into())
}

/// Return random bytes from Aranya's CSPRNG.
///
/// This method can be used to generate a PSK seed IKM for the QUIC syncer.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[out] buf buffer where random bytes are written to.
/// @param[in] buf_len the size of the buffer.
///
/// @relates AranyaClient.
pub unsafe fn rand(client: &Client, buf: &mut [MaybeUninit<u8>]) {
    buf.fill(MaybeUninit::new(0));
    // SAFETY: We just initialized the buf and are removing MaybeUninit.
    let buf = unsafe { slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len()) };

    client.rt.block_on(client.inner.rand(buf));
}

/// Return serialized PSK seed encrypted for another device on the team.
///
/// The PSK seed will be encrypted using the public encryption key of the specified device on the team.
///
/// Returns an `AranyaBufferTooSmall` error if the output buffer is too small to hold the seed bytes.
/// Writes the number of bytes that would have been returned to `seed_len`.
/// The application can use `seed_len` to allocate a larger buffer.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team_id the team's ID [`TeamId`].
/// @param[in] keybundle serialized keybundle byte buffer `KeyBundle`.
/// @param[in] keybundle_len the length of the keybundle
/// @param[out] seed the serialized, encrypted PSK seed.
/// @param[in,out] seed_len the number of bytes written to the seed buffer.
///
/// This method will be removed soon since certificates will be used instead of PSKs in the future.
///
/// @relates AranyaClient.
pub unsafe fn encrypt_psk_seed_for_peer(
    client: &Client,
    team_id: &TeamId,
    keybundle: &[u8],
    seed: *mut MaybeUninit<u8>,
    seed_len: &mut usize,
) -> Result<(), imp::Error> {
    let keybundle = imp::key_bundle_deserialize(keybundle)?;

    let wrapped_seed = client.rt.block_on(
        client
            .inner
            .team(team_id.into())
            .encrypt_psk_seed_for_peer(&keybundle.encryption),
    )?;

    if *seed_len < wrapped_seed.len() {
        *seed_len = wrapped_seed.len();
        return Err(imp::Error::BufferTooSmall);
    }
    *seed_len = wrapped_seed.len();
    let out = aranya_capi_core::try_as_mut_slice!(seed, *seed_len);
    for (dst, src) in out.iter_mut().zip(&wrapped_seed) {
        dst.write(*src);
    }

    Ok(())
}

/// Add a team to the local device store.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] cfg the Team Configuration [`AddTeamConfig`].
///
/// @relates AranyaClient.
pub fn add_team(client: &Client, cfg: &AddTeamConfig) -> Result<(), imp::Error> {
    let cfg: &imp::AddTeamConfig = cfg.deref();
    client.rt.block_on(client.inner.add_team(cfg.into()))?;
    Ok(())
}

/// Remove a team from local device storage.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
///
/// @relates AranyaClient.
pub fn remove_team(client: &Client, team: &TeamId) -> Result<(), imp::Error> {
    client.rt.block_on(client.inner.remove_team(team.into()))?;
    Ok(())
}

/// Close the team and stop all operations on the graph.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
///
/// @relates AranyaClient.
pub fn close_team(client: &Client, team: &TeamId) -> Result<(), imp::Error> {
    client
        .rt
        .block_on(client.inner.team(team.into()).close_team())?;
    Ok(())
}

/// Add a device to the team with the default role.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] keybundle serialized keybundle byte buffer `KeyBundle`.
/// @param[in] keybundle_len is the length of the serialized keybundle.
/// @param[in] role_id (optional) the ID of the role to assign to the device.
///
/// @relates AranyaClient.
pub unsafe fn add_device_to_team(
    client: &Client,
    team: &TeamId,
    keybundle: &[u8],
    role_id: Option<&RoleId>,
) -> Result<(), imp::Error> {
    let keybundle = imp::key_bundle_deserialize(keybundle)?;

    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .add_device(keybundle, role_id.map(Into::into)),
    )?;
    Ok(())
}

/// Remove a device from the team.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
///
/// @relates AranyaClient.
pub fn remove_device_from_team(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
) -> Result<(), imp::Error> {
    client
        .rt
        .block_on(client.inner.team(team.into()).remove_device(device.into()))?;
    Ok(())
}

/// Add the peer for automatic periodic Aranya state syncing.
///
/// If a peer is not reachable on the network, sync errors
/// will appear in the tracing logs and
/// Aranya will be unable to sync state with that peer.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] addr the peer's Aranya network address [`Addr`].
/// @param[in] config configuration values for syncing with a peer.
///
/// @relates AranyaClient.
pub unsafe fn add_sync_peer(
    client: &Client,
    team: &TeamId,
    addr: Addr,
    config: &SyncPeerConfig,
) -> Result<(), imp::Error> {
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
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] addr the peer's Aranya network address [`Addr`].
///
/// @relates AranyaClient.
pub unsafe fn remove_sync_peer(
    client: &Client,
    team: &TeamId,
    addr: Addr,
) -> Result<(), imp::Error> {
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
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] addr the peer's Aranya network address [`Addr`].
/// @param[in] config configuration values for syncing with a peer.
///
/// Default values for a sync config will be used if `config` is `NULL`
///
/// @relates AranyaClient.
pub unsafe fn sync_now(
    client: &Client,
    team: &TeamId,
    addr: Addr,
    config: Option<&SyncPeerConfig>,
) -> Result<(), imp::Error> {
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
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[out] devices returns a list of device IDs on the team [`DeviceId`].
/// @param[in,out] devices_len returns the length of the devices list [`DeviceId`].
///
/// @relates AranyaClient.
pub unsafe fn team_devices(
    client: &Client,
    team: &TeamId,
    devices: *mut MaybeUninit<DeviceId>,
    devices_len: &mut usize,
) -> Result<(), imp::Error> {
    let data = client
        .rt
        .block_on(client.inner.team(team.into()).devices())?;
    let data = data.__data();
    let out = aranya_capi_core::try_as_mut_slice!(devices, *devices_len);
    if *devices_len < data.len() {
        *devices_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    }
    *devices_len = data.len();
    for (dst, src) in out.iter_mut().zip(data) {
        dst.write((*src).into());
    }
    Ok(())
}

// TODO: query_device_role

/// Query device's keybundle.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[out] keybundle keybundle byte buffer `KeyBundle`.
/// @param[in,out] keybundle_len returns the length of the serialized keybundle.
///
/// @relates AranyaClient.
pub unsafe fn team_device_keybundle(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    keybundle: *mut MaybeUninit<u8>,
    keybundle_len: &mut usize,
) -> Result<(), imp::Error> {
    let keys = client.rt.block_on(
        client
            .inner
            .team(team.into())
            .device(device.into())
            .keybundle(),
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
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[out] labels returns a list of labels assigned to the device [`LabelId`].
/// @param[in,out] labels_len returns the length of the labels list [`LabelId`].
///
/// @relates AranyaClient.
pub unsafe fn team_device_label_assignments(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    labels: *mut MaybeUninit<LabelId>,
    labels_len: &mut usize,
) -> Result<(), imp::Error> {
    let data = client.rt.block_on(
        client
            .inner
            .team(team.into())
            .device(device.into())
            .label_assignments(),
    )?;
    let data = data.__data();
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

/// Query for list of existing labels.
///
/// Returns an `AranyaBufferTooSmall` error if the output buffer is too small to hold the labels.
/// Writes the number of labels that would have been returned to `labels_len`.
/// The application can use `labels_len` to allocate a larger buffer.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[out] labels returns a list of labels [`LabelId`].
/// @param[in,out] labels_len returns the length of the labels list [`LabelId`].
///
/// @relates AranyaClient.
pub unsafe fn team_labels(
    client: &Client,
    team: &TeamId,
    labels: *mut MaybeUninit<LabelId>,
    labels_len: &mut usize,
) -> Result<(), imp::Error> {
    let data = client
        .rt
        .block_on(client.inner.team(team.into()).labels())?;
    let data = data.__data();
    if *labels_len < data.len() {
        *labels_len = data.len();
        return Err(imp::Error::BufferTooSmall);
    }
    *labels_len = data.len();
    let out = aranya_capi_core::try_as_mut_slice!(labels, *labels_len);
    for (dst, src) in out.iter_mut().zip(data) {
        dst.write(src.id.into());
    }
    Ok(())
}

/// Query if a label exists.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[in] label the label [`LabelId`].
/// @param[out] __output boolean indicating whether the label exists.
///
/// @relates AranyaClient.
pub unsafe fn team_label_exists(
    client: &Client,
    team: &TeamId,
    label: &LabelId,
) -> Result<bool, imp::Error> {
    let label_result = client
        .rt
        .block_on(client.inner.team(team.into()).label(label.into()))?;
    let exists = label_result.is_some();
    Ok(exists)
}

/// An AFC Sending Channel Object.
#[cfg(feature = "afc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 120, align = 8)]
pub type AfcSendChannel = Safe<afc::SendChannel>;

/// An AFC Receiving Channel Object.
#[cfg(feature = "afc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 120, align = 8)]
pub type AfcReceiveChannel = Safe<afc::ReceiveChannel>;

/// An AFC Control Message, used to create the other end of a channel.
///
/// In order to access the underlying buffer to send to a peer, you'll need to
/// call `aranya_afc_ctrl_msg_get_bytes()`.
#[cfg(feature = "afc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 32, align = 8)]
pub type AfcCtrlMsg = Safe<afc::CtrlMsg>;

/// An AFC Sequence Number, for reordering messages.
///
/// You can compare two sequence numbers using `aranya_afc_seq_cmp()`.
#[cfg(feature = "afc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 24, align = 8)]
pub type AfcSeq = Safe<afc::Seq>;

/// The overhead needed for a channel message.
///
/// Note that the ciphertext buffer must be at least `plaintext_len` +
/// `aranya_afc_channel_overhead()` long.
#[cfg(feature = "afc")]
pub const ARANYA_AFC_CHANNEL_OVERHEAD: usize = 24;

#[allow(unused_qualifications)]
#[cfg(feature = "afc")]
const _: () = {
    assert!(ARANYA_AFC_CHANNEL_OVERHEAD == aranya_client::afc::Channels::OVERHEAD);
};

/// Create a send-only AFC channel between this device and a peer.
///
/// Note that the control message needs to be sent to the other peer using the
/// transport of your choice to create the other side of the channel.
///
/// Permission to perform this operation is checked against the Aranya policy.
/// Both the current node and its peer should have permission to use the label
/// and have appropriate channel permissions.
///
/// @param[in]  client the Aranya Client [`Client`].
/// @param[in]  team_id the team's identifier [`TeamId`].
/// @param[in]  peer_id the peer's identifier [`DeviceId`].
/// @param[in]  label_id the label identifier [`LabelId`] to create the channel with.
/// @param[out] channel the AFC channel object [`AfcSendChannel`].
/// @param[out] control the AFC control message [`AfcCtrlMsg`]
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn afc_create_uni_send_channel(
    client: &Client,
    team_id: &TeamId,
    peer_id: &DeviceId,
    label_id: &LabelId,
    channel: &mut MaybeUninit<AfcSendChannel>,
    control: &mut MaybeUninit<AfcCtrlMsg>,
) -> Result<(), imp::Error> {
    let (chan, ctrl) = client
        .rt
        .block_on(client.inner.afc().create_uni_send_channel(
            team_id.into(),
            peer_id.into(),
            label_id.into(),
        ))?;

    AfcSendChannel::init(channel, chan);
    AfcCtrlMsg::init(control, ctrl);
    Ok(())
}

/// Use an ephemeral command to create an AFC channel between this device and a peer.
///
/// @param[in]  client the Aranya Client [`Client`].
/// @param[in]  team_id the team's identifier [`TeamId`].
/// @param[in]  control the AFC control message.
/// @param[out] channel the AFC channel object [`AfcReceiveChannel`].
/// @param[out] __output the corresponding AFC channel type [`AfcChannelType`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn afc_recv_ctrl(
    client: &Client,
    team_id: &TeamId,
    control: &[u8],
    channel: &mut MaybeUninit<AfcReceiveChannel>,
) -> Result<(), imp::Error> {
    let ctrl = Vec::from(control).into_boxed_slice();
    let chan = client
        .rt
        .block_on(client.inner.afc().recv_ctrl(team_id.into(), ctrl.into()))?;
    AfcReceiveChannel::init(channel, chan);
    Ok(())
}

/// Returns the [`LabelId`] for the associated [`AfcSendChannel`].
///
/// @param[in]  channel the AFC channel object [`AfcSendChannel`].
/// @param[out] __output the corresponding label ID [`LabelId`].
#[cfg(feature = "afc")]
pub fn afc_send_channel_get_label_id(channel: &AfcSendChannel) -> LabelId {
    channel.label_id().into()
}

/// Returns the [`AfcChannelId`] for the associated [`AfcSendChannel`].
///
/// @param[in]  channel the AFC channel object [`AfcSendChannel`].
/// @param[out] __output the corresponding channel ID [`AfcChannelId`].
#[cfg(feature = "afc")]
pub fn afc_send_channel_get_id(channel: &AfcSendChannel) -> AfcChannelId {
    channel.id().into()
}

/// Returns the [`LabelId`] for the associated [`AfcReceiveChannel`].
///
/// @param[in]  channel the AFC channel object [`AfcReceiveChannel`].
/// @param[out] __output the corresponding label ID [`LabelId`].
#[cfg(feature = "afc")]
pub fn afc_receive_channel_get_label_id(channel: &AfcReceiveChannel) -> LabelId {
    channel.label_id().into()
}

/// Returns the [`AfcChannelId`] for the associated [`AfcReceiveChannel`].
///
/// @param[in]  channel the AFC channel object [`AfcReceiveChannel`].
/// @param[out] __output the corresponding channel ID [`AfcChannelId`].
#[cfg(feature = "afc")]
pub fn afc_receive_channel_get_id(channel: &AfcReceiveChannel) -> AfcChannelId {
    channel.id().into()
}

/// Returns the raw data for a given [`AfcCtrlMsg`].
///
/// Note that the lifetime of the pointer is tied to the [`AfcCtrlMsg`].
///
/// @param[in]  control the control message produced by creating a channel.
/// @param[out] ptr the raw pointer of the stored buffer.
/// @param[out] len the raw length of the stored buffer.
#[cfg(feature = "afc")]
pub fn afc_ctrl_msg_get_bytes(
    control: &AfcCtrlMsg,
    ptr: &mut MaybeUninit<*const u8>,
    len: &mut MaybeUninit<usize>,
) {
    let slice = control.as_bytes();
    ptr.write(slice.as_ptr());
    len.write(slice.len());
}

/// Returns the three-way comparison between `seq1` and `seq2`.
///
/// @param[in]  seq1 the first sequence number to compare.
/// @param[in]  seq1 the second sequence number to compare.
/// @param[out] __output the comparison result (-1 is <, 0 is =, 1 is >).
#[cfg(feature = "afc")]
pub fn afc_seq_cmp(seq1: &AfcSeq, seq2: &AfcSeq) -> core::ffi::c_int {
    afc::Seq::cmp(seq1, seq2) as core::ffi::c_int
}

/// Encrypts and authenticates `plaintext`, and writes it to `dst`.
///
/// Note that `dst` must be at least `plaintext.len()` + `aranya_afc_channel_overhead()`,
/// or the function will return an error (`InvalidArgument` or `BufferTooSmall`).
///
/// @param[in]  channel the AFC channel object [`AfcSendChannel`].
/// @param[in]  plaintext the message being encrypted.
/// @param[out] dst the output buffer the ciphertext is written to.
#[cfg(feature = "afc")]
pub unsafe fn afc_channel_seal(
    channel: &AfcSendChannel,
    plaintext: &[u8],
    dst: *mut u8,
    dst_len: &mut usize,
) -> Result<(), imp::Error> {
    if dst.is_null() || *dst_len == 0 {
        return Err(
            InvalidArg::new("dst", "Tried to call afc_channel_seal with an empty buffer").into(),
        );
    }

    if *dst_len < (plaintext.len() + ARANYA_AFC_CHANNEL_OVERHEAD) {
        return Err(imp::Error::BufferTooSmall);
    }

    // SAFETY: the user is responsible for giving us a valid pointer.
    let dst = aranya_capi_core::try_as_mut_slice!(dst, *dst_len);
    channel.seal(dst, plaintext)?;
    *dst_len = plaintext.len() + ARANYA_AFC_CHANNEL_OVERHEAD;

    Ok(())
}

/// Decrypts and authenticates `ciphertext`, and writes it to `dst`.
///
/// Note that `dst` must be at least `ciphertext.len()` - `aranya_afc_channel_overhead()`,
/// or the function will return an error (`InvalidArgument` or `BufferTooSmall`).
///
/// @param[in]  channel the AFC channel object [`AfcReceiveChannel`].
/// @param[in]  ciphertext the message being decrypted.
/// @param[out] dst the output buffer the message is written to.
/// @param[out] seq the sequence number for the opened message, for reordering.
#[cfg(feature = "afc")]
pub unsafe fn afc_channel_open(
    channel: &AfcReceiveChannel,
    ciphertext: &[u8],
    dst: *mut u8,
    dst_len: &mut usize,
    seq: &mut MaybeUninit<AfcSeq>,
) -> Result<(), imp::Error> {
    if dst.is_null() || *dst_len == 0 {
        return Err(
            InvalidArg::new("dst", "Tried to call afc_channel_open with an empty buffer").into(),
        );
    }

    if *dst_len < (ciphertext.len() - ARANYA_AFC_CHANNEL_OVERHEAD) {
        return Err(imp::Error::BufferTooSmall);
    }

    // SAFETY: the user is responsible for giving us a valid pointer.
    let dst = aranya_capi_core::try_as_mut_slice!(dst, *dst_len);
    let seq_raw = channel.open(dst, ciphertext)?;

    AfcSeq::init(seq, seq_raw);
    // Do our best to set a max bound, even if we can't know if they pass in a larger ciphertext than needed.
    *dst_len = ciphertext.len() - ARANYA_AFC_CHANNEL_OVERHEAD;

    Ok(())
}

/// Removes an [`AfcSendChannel`] from use.
///
/// Note that this function takes ownership of the [`AfcSendChannel`] and invalidates
/// any further use (i.e. calling seal).
///
/// @param[in]  client the Aranya Client [`Client`].
/// @param[in]  channel the AFC channel object [`AfcSendChannel`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn afc_send_channel_delete(
    client: &Client,
    channel: OwnedPtr<AfcSendChannel>,
) -> Result<(), imp::Error> {
    // SAFETY: the user is responsible for passing in a valid `AfcSendChannel` pointer.
    let channel = unsafe { channel.read().into_inner().into_inner() };
    client.rt.block_on(channel.delete())?;
    Ok(())
}

/// Removes an [`AfcReceiveChannel`] from use.
///
/// Note that this function takes ownership of the [`AfcReceiveChannel`] and invalidates
/// any further use (i.e. calling seal).
///
/// @param[in]  client the Aranya Client [`Client`].
/// @param[in]  channel the AFC channel object [`AfcReceiveChannel`].
///
/// @relates AranyaClient.
#[cfg(feature = "afc")]
pub fn afc_receive_channel_delete(
    client: &Client,
    channel: OwnedPtr<AfcReceiveChannel>,
) -> Result<(), imp::Error> {
    // SAFETY: the user is responsible for passing in a valid `AfcReceiveChannel` pointer.
    let channel = unsafe { channel.read().into_inner().into_inner() };
    client.rt.block_on(channel.delete())?;
    Ok(())
}
