#![allow(rustdoc::broken_intra_doc_links)]
use core::{
    ffi::{c_char, CStr},
    ptr, slice,
};
#[cfg(feature = "aqc")]
use std::str::FromStr;
use std::{ffi::OsStr, ops::Deref, os::unix::ffi::OsStrExt};

use anyhow::Context as _;
#[cfg(feature = "aqc")]
use aranya_capi_core::opaque::Opaque;
use aranya_capi_core::{prelude::*, ErrorCode, InvalidArg};
#[cfg(feature = "aqc")]
use aranya_client::aqc::{self, AqcPeerStream};
use aranya_daemon_api::Text;
use aranya_util::error::ReportExt as _;
#[cfg(feature = "aqc")]
use bytes::Bytes;
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

    /// AQC library error.
    #[cfg(feature = "aqc")]
    #[capi(msg = "AQC library error")]
    Aqc,

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
                #[cfg(feature = "aqc")]
                aranya_client::Error::Aqc(_) => Self::Aqc,
                aranya_client::Error::Bug(_) => Self::Bug,
                aranya_client::Error::Config(_) => Self::Config,
                aranya_client::Error::Other(_) => Self::Other,
                _ => {
                    error!("forgot to implement an error variant");
                    Self::Bug
                }
            },
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

    #[cfg(feature = "aqc")]
    let aqc_addr = {
        // SAFETY: Caller must ensure pointer is a valid C String.
        let aqc_str = unsafe { CStr::from_ptr(config.aqc_addr()) }
            .to_str()
            .context("unable to convert to string")?;

        aranya_util::Addr::from_str(aqc_str)?
    };

    let inner = rt.block_on({
        let mut builder = aranya_client::Client::builder();
        builder = builder.daemon_uds_path(daemon_socket);
        #[cfg(feature = "aqc")]
        {
            builder = builder.aqc_server_addr(&aqc_addr);
        }
        builder.connect()
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
    assert!(ARANYA_ID_LEN == size_of::<aranya_crypto::Id>());
};

/// Cryptographically secure Aranya ID.
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

/// The size in bytes of a PSK seed IKM.
pub const ARANYA_SEED_IKM_LEN: usize = 32;

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

/// An AQC label name.
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

/// A network identifier for an Aranya client.
///
/// E.g. "localhost:8080", "127.0.0.1:8080"
#[cfg(feature = "aqc")]
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct NetIdentifier(*const c_char);

#[cfg(feature = "aqc")]
impl NetIdentifier {
    unsafe fn as_underlying(self) -> Result<aranya_daemon_api::NetIdentifier, imp::Error> {
        // SAFETY: Caller must ensure the pointer is a valid C String.
        let cstr = unsafe { CStr::from_ptr(self.0) };
        Ok(aranya_daemon_api::NetIdentifier(Text::try_from(cstr)?))
    }
}

/// Channel ID for AQC bidi channel.
#[cfg(feature = "aqc")]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AqcBidiChannelId {
    id: Id,
}

#[cfg(feature = "aqc")]
impl From<aranya_daemon_api::AqcBidiChannelId> for AqcBidiChannelId {
    fn from(value: aranya_daemon_api::AqcBidiChannelId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

#[cfg(feature = "aqc")]
impl From<&AqcBidiChannelId> for aranya_daemon_api::AqcBidiChannelId {
    fn from(value: &AqcBidiChannelId) -> Self {
        value.id.bytes.into()
    }
}

/// Channel ID for AQC uni channel.
#[cfg(feature = "aqc")]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AqcUniChannelId {
    id: Id,
}

#[cfg(feature = "aqc")]
impl From<aranya_daemon_api::AqcUniChannelId> for AqcUniChannelId {
    fn from(value: aranya_daemon_api::AqcUniChannelId) -> Self {
        Self {
            id: Id {
                bytes: value.into(),
            },
        }
    }
}

#[cfg(feature = "aqc")]
impl From<&AqcUniChannelId> for aranya_daemon_api::AqcUniChannelId {
    fn from(value: &AqcUniChannelId) -> Self {
        value.id.bytes.into()
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
    let client = client.imp();
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

    aranya_crypto::Id::decode(cstr.to_bytes())
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
    let client = client.imp();
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

/// Configuration info for Aranya QUIC Channels.
///
/// Use a [`AqcConfigBuilder`] to construct this object.
#[cfg(feature = "aqc")]
#[aranya_capi_core::opaque(size = 40, align = 8)]
pub type AqcConfig = Safe<imp::AqcConfig>;

/// Configuration info builder for Aranya QUIC Channels config [`AqcConfig`].
#[cfg(feature = "aqc")]
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 24, align = 8)]
pub type AqcConfigBuilder = Safe<imp::AqcConfigBuilder>;

/// Attempts to construct an [`AqcConfig`].
///
/// This function consumes and releases any resources associated
/// with the memory pointed to by `cfg`.
///
/// @param[in] cfg a pointer to the aqc config builder
/// @param[out] out a pointer to write the aqc config to
///
/// @relates AranyaAqcConfigBuilder.
#[cfg(feature = "aqc")]
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
/// @param[in,out] cfg a pointer to the aqc config builder
/// @param[in] address a string with the address to bind to
///
/// @relates AranyaAqcConfigBuilder.
#[cfg(feature = "aqc")]
pub fn aqc_config_builder_set_address(cfg: &mut AqcConfigBuilder, address: *const c_char) {
    cfg.addr(address);
}

/// Sets the configuration for Aranya QUIC Channels.
///
/// @param[in,out] cfg a pointer to the client config builder
/// @param[in] aqc_config a pointer to a valid AQC config (see [`AqcConfigBuilder`])
///
/// @relates AranyaAqcConfigBuilder.
#[cfg(feature = "aqc")]
pub fn client_config_builder_set_aqc_config(cfg: &mut ClientConfigBuilder, aqc_config: &AqcConfig) {
    cfg.aqc((**aqc_config).clone());
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
pub fn sync_peer_config_builder_set_interval(
    cfg: &mut SyncPeerConfigBuilder,
    interval: Duration,
) -> Result<(), imp::Error> {
    // Check that interval doesn't exceed 1 year to prevent overflow when adding to Instant::now()
    // in DelayQueue::insert() (which calculates deadline as current_time + interval)
    let one_year = std::time::Duration::from_secs(365 * 24 * 60 * 60); // 365 days
    if std::time::Duration::from(interval) > one_year {
        return Err(
            InvalidArg::new("interval", "must not exceed 1 year to prevent overflow").into(),
        );
    }

    cfg.interval(interval);
    Ok(())
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

/// Enables automatic syncing when a hello message is received from this peer
/// indicating they have a head that we don't have.
///
/// By default, sync on hello is disabled.
/// @param[in,out] cfg a pointer to the builder for a sync config
///
/// @relates AranyaSyncPeerConfigBuilder.
pub fn sync_peer_config_builder_set_sync_on_hello(cfg: &mut SyncPeerConfigBuilder) {
    cfg.sync_on_hello(true);
}

/// Assign a role to a device.
///
/// This will change the device's current role to the new role assigned.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[in] role the role [`Role`] to assign to the device.
///
/// @relates AranyaClient.
pub fn assign_role(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    role: Role,
) -> Result<(), imp::Error> {
    let client = client.imp();
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
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[in] role the role [`Role`] to revoke from the device.
///
/// @relates AranyaClient.
pub fn revoke_role(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    role: Role,
) -> Result<(), imp::Error> {
    let client = client.imp();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .revoke_role(device.into(), role.into()),
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
///
/// @relates AranyaClient.
pub fn create_label(
    client: &Client,
    team: &TeamId,
    name: LabelName,
) -> Result<LabelId, imp::Error> {
    let client = client.imp();
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
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] label_id the channel label ID [`LabelId`] to delete.
///
/// @relates AranyaClient.
pub fn delete_label(client: &Client, team: &TeamId, label_id: &LabelId) -> Result<(), imp::Error> {
    let client = client.imp();
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
/// @param[in] label_id the AQC channel label ID [`LabelId`].
///
/// @relates AranyaClient.
pub fn assign_label(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    label_id: &LabelId,
    op: ChanOp,
) -> Result<(), imp::Error> {
    let client = client.imp();
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
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device ID [`DeviceId`] of the device to revoke the label from.
/// @param[in] label_id the AQC channel label ID [`LabelId`].
///
/// @relates AranyaClient.
pub fn revoke_label(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    label_id: &LabelId,
) -> Result<(), imp::Error> {
    let client = client.imp();
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
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] cfg the Team Configuration [`CreateTeamConfig`].
/// @param[out] __output the team's ID [`TeamId`].
///
/// @relates AranyaClient.
pub fn create_team(client: &Client, cfg: &CreateTeamConfig) -> Result<TeamId, imp::Error> {
    let client = client.imp();
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
pub unsafe fn rand(client: &Client, buf: &mut [MaybeUninit<u8>]) {
    let client = client.imp();

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
    let client = client.imp();
    let keybundle = imp::key_bundle_deserialize(keybundle)?;

    let wrapped_seed = client.rt.block_on(
        client
            .inner
            .team(team_id.into())
            .encrypt_psk_seed_for_peer(&keybundle.encoding),
    )?;

    if *seed_len < wrapped_seed.len() {
        *seed_len = wrapped_seed.len();
        return Err(imp::Error::BufferTooSmall);
    }
    let out = aranya_capi_core::try_as_mut_slice!(seed, *seed_len);
    for (dst, src) in out.iter_mut().zip(&wrapped_seed) {
        dst.write(*src);
    }
    *seed_len = wrapped_seed.len();

    Ok(())
}

/// Add a team to the local device store.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] cfg the Team Configuration [`AddTeamConfig`].
///
/// @relates AranyaClient.
pub fn add_team(client: &Client, cfg: &AddTeamConfig) -> Result<(), imp::Error> {
    let client = client.imp();
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
    let client = client.imp();
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
    let client = client.imp();
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
///
/// @relates AranyaClient.
pub unsafe fn add_device_to_team(
    client: &Client,
    team: &TeamId,
    keybundle: &[u8],
) -> Result<(), imp::Error> {
    let client = client.imp();
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
    let client = client.imp();
    client.rt.block_on(
        client
            .inner
            .team(team.into())
            .remove_device_from_team(device.into()),
    )?;
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
    let client = client.imp();
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
    let client = client.imp();
    // SAFETY: Caller must ensure `addr` is a valid C String.
    let addr = unsafe { addr.as_underlying() }?;
    client
        .rt
        .block_on(client.inner.team(team.into()).remove_sync_peer(addr))?;
    Ok(())
}

/// Subscribe to hello notifications from a sync peer.
///
/// This will request the peer to send hello notifications when their graph head changes.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] peer the peer's Aranya network address [`Addr`].
/// @param[in] delay minimum delay between notifications.
/// @param[in] duration how long the subscription should remain active.
///
/// @relates AranyaClient.
pub unsafe fn sync_hello_subscribe(
    client: &Client,
    team: &TeamId,
    peer: Addr,
    delay: Duration,
    duration: Duration,
) -> Result<(), imp::Error> {
    // SAFETY: Caller must ensure `addr` is a valid C String.
    let addr = unsafe { peer.as_underlying() }?;
    client
        .rt
        .block_on(client.inner.team(team.into()).sync_hello_subscribe(
            addr,
            delay.into(),
            duration.into(),
        ))?;
    Ok(())
}

/// Unsubscribe from hello notifications from a sync peer.
///
/// This will stop receiving hello notifications from the specified peer.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] addr the peer's Aranya network address [`Addr`].
///
/// @relates AranyaClient.
pub unsafe fn sync_hello_unsubscribe(
    client: &Client,
    team: &TeamId,
    peer: Addr,
) -> Result<(), imp::Error> {
    // SAFETY: Caller must ensure `addr` is a valid C String.
    let addr = unsafe { peer.as_underlying() }?;
    client
        .rt
        .block_on(client.inner.team(team.into()).sync_hello_unsubscribe(addr))?;
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
    let client = client.imp();
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
pub unsafe fn query_devices_on_team(
    client: &Client,
    team: &TeamId,
    devices: *mut MaybeUninit<DeviceId>,
    devices_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.imp();
    let data = client
        .rt
        .block_on(client.inner.team(team.into()).queries().devices_on_team())?;
    let data = data.__data();
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
pub unsafe fn query_device_keybundle(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    keybundle: *mut MaybeUninit<u8>,
    keybundle_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.imp();
    let keys = client.rt.block_on(
        client
            .inner
            .team(team.into())
            .queries()
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
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[out] labels returns a list of labels assigned to the device [`LabelId`].
/// @param[in,out] labels_len returns the length of the labels list [`LabelId`].
///
/// @relates AranyaClient.
pub unsafe fn query_device_label_assignments(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    labels: *mut MaybeUninit<LabelId>,
    labels_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.imp();
    let data = client.rt.block_on(
        client
            .inner
            .team(team.into())
            .queries()
            .device_label_assignments(device.into()),
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
pub unsafe fn query_labels(
    client: &Client,
    team: &TeamId,
    labels: *mut MaybeUninit<LabelId>,
    labels_len: &mut usize,
) -> Result<(), imp::Error> {
    let client = client.imp();
    let data = client
        .rt
        .block_on(client.inner.team(team.into()).queries().labels())?;
    let data = data.__data();
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

/// Query if a label exists.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[in] label the label [`LabelId`].
/// @param[out] __output boolean indicating whether the label exists.
///
/// @relates AranyaClient.
pub unsafe fn query_label_exists(
    client: &Client,
    team: &TeamId,
    label: &LabelId,
) -> Result<bool, imp::Error> {
    let client = client.imp();
    let exists = client.rt.block_on(
        client
            .inner
            .team(team.into())
            .queries()
            .label_exists(label.into()),
    )?;
    Ok(exists)
}

/// Query device's AQC network identifier.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[out] ident network identifier string [`NetIdentifier`].
/// @param[in,out] length of ident
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub unsafe fn query_aqc_net_identifier(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    ident: *mut MaybeUninit<c_char>,
    ident_len: &mut usize,
) -> Result<bool, imp::Error> {
    let client = client.imp();
    let Some(net_identifier) = client.rt.block_on(
        client
            .inner
            .team(team.into())
            .queries()
            .aqc_net_identifier(device.into()),
    )?
    else {
        return Ok(false);
    };
    let ident = aranya_capi_core::try_as_mut_slice!(ident, *ident_len);
    aranya_capi_core::write_c_str(ident, &net_identifier, ident_len)?;
    Ok(true)
}

/// Associate a network identifier to a device for use with AQC.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// If the address already exists for this device, it is replaced with the new address. Capable
/// of resolving addresses via DNS, required to be statically mapped to IPV4. For use with
/// OpenChannel and receiving messages. Can take either DNS name or IPV4.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[in] net_identifier the device's network identifier [`NetIdentifier`].
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub unsafe fn aqc_assign_net_identifier(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    net_identifier: NetIdentifier,
) -> Result<(), imp::Error> {
    let client = client.imp();
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
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] team the team's ID [`TeamId`].
/// @param[in] device the device's ID [`DeviceId`].
/// @param[in] net_identifier the device's network identifier [`NetIdentifier`].
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub unsafe fn aqc_remove_net_identifier(
    client: &Client,
    team: &TeamId,
    device: &DeviceId,
    net_identifier: NetIdentifier,
) -> Result<(), imp::Error> {
    let client = client.imp();
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

/// A type containing the AQC channel variant.
///
/// Note that this data is only valid after a successful call to
/// `try_receive_channel`, and is invalidated after calling
/// `get_bidi_channel`/`get_receive_channel`.
#[cfg(feature = "aqc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 168, align = 8)]
pub type AqcPeerChannel = Safe<imp::AqcPeerChannel>;

/// An enum containing all [`AqcPeerChannel`] variants.
#[cfg(feature = "aqc")]
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum AqcChannelType {
    Bidirectional,
    Receiver,
}

/// An AQC Bidirectional Channel Object.
#[cfg(feature = "aqc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 160, align = 8)]
pub type AqcBidiChannel = Safe<imp::AqcBidiChannel>;

/// An AQC Sender Channel Object.
#[cfg(feature = "aqc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 160, align = 8)]
pub type AqcSendChannel = Safe<imp::AqcSendChannel>;

/// An AQC Receiver Channel Object.
#[cfg(feature = "aqc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 160, align = 8)]
pub type AqcReceiveChannel = Safe<imp::AqcReceiveChannel>;

/// An AQC Bidirectional Stream Object.
#[cfg(feature = "aqc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 208, align = 8)]
pub type AqcBidiStream = Safe<imp::AqcBidiStream>;

/// An AQC Sender Stream Object.
#[cfg(feature = "aqc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 176, align = 8)]
pub type AqcSendStream = Safe<imp::AqcSendStream>;

/// An AQC Receiver Stream Object.
#[cfg(feature = "aqc")]
#[aranya_capi_core::derive(Cleanup)]
#[aranya_capi_core::opaque(size = 208, align = 8)]
pub type AqcReceiveStream = Safe<imp::AqcReceiveStream>;

/// Create a bidirectional AQC channel between this device and a peer.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in]  client the Aranya Client [`Client`].
/// @param[in]  team the team's ID [`TeamId`].
/// @param[in]  peer the peer's network identifier [`NetIdentifier`].
/// @param[in]  label_id the AQC channel label ID [`LabelId`] to create the channel with.
/// @param[out] channel the AQC channel object [`AqcBidiChannel`].
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub unsafe fn aqc_create_bidi_channel(
    client: &Client,
    team: &TeamId,
    peer: NetIdentifier,
    label_id: &LabelId,
    channel: &mut MaybeUninit<AqcBidiChannel>,
) -> Result<(), imp::Error> {
    // SAFETY: Caller must ensure `peer` is a valid C String.
    let peer = unsafe { peer.as_underlying() }?;

    let client = client.imp();
    let chan = client.rt.block_on(
        client
            .inner
            .aqc()
            .ok_or(imp::Error::NotEnabled)?
            .create_bidi_channel(team.into(), peer, label_id.into()),
    )?;

    AqcBidiChannel::init(channel, imp::AqcBidiChannel::new(chan));
    Ok(())
}

/// Create a unidirectional AQC channel between this device and a peer.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param[in]  client the Aranya Client [`Client`].
/// @param[in]  team the team's ID [`TeamId`].
/// @param[in]  peer the peer's network identifier [`NetIdentifier`].
/// @param[in]  label_id the AQC channel label ID [`LabelId`] to create the channel with.
/// @param[out] channel the AQC channel object [`AqcSendChannel`].
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub unsafe fn aqc_create_uni_channel(
    client: &Client,
    team: &TeamId,
    peer: NetIdentifier,
    label_id: &LabelId,
    channel: &mut MaybeUninit<AqcSendChannel>,
) -> Result<(), imp::Error> {
    // SAFETY: Caller must ensure `peer` is a valid C String.
    let peer = unsafe { peer.as_underlying() }?;

    let client = client.imp();
    let chan = client.rt.block_on(
        client
            .inner
            .aqc()
            .ok_or(imp::Error::NotEnabled)?
            .create_uni_channel(team.into(), peer, label_id.into()),
    )?;

    AqcSendChannel::init(channel, imp::AqcSendChannel::new(chan));
    Ok(())
}

/// Delete a bidirectional AQC channel.
/// Zeroizes PSKs associated with the channel.
/// Closes all associated QUIC connections and streams.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] channel the AQC Channel [`AqcBidiChannel`] to delete.
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_delete_bidi_channel(
    client: &Client,
    channel: &mut AqcBidiChannel,
) -> Result<(), imp::Error> {
    let client = client.imp();
    client.rt.block_on(
        client
            .inner
            .aqc()
            .ok_or(imp::Error::NotEnabled)?
            .delete_bidi_channel(&mut channel.inner),
    )?;
    Ok(())
}

/// Delete a send unidirectional AQC channel.
/// Zeroizes PSKs associated with the channel.
/// Closes all associated QUIC connections and streams.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] channel the AQC Channel [`AqcSendChannel`] to delete.
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_delete_send_uni_channel(
    client: &Client,
    channel: &mut AqcSendChannel,
) -> Result<(), imp::Error> {
    let client = client.imp();
    client.rt.block_on(
        client
            .inner
            .aqc()
            .ok_or(imp::Error::NotEnabled)?
            .delete_send_uni_channel(&mut channel.inner),
    )?;
    Ok(())
}

/// Delete a receive unidirectional AQC channel.
/// Zeroizes PSKs associated with the channel.
/// Closes all associated QUIC connections and streams.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] channel the AQC Channel [`AqcReceiveChannel`] to delete.
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_delete_receive_uni_channel(
    client: &Client,
    channel: &mut AqcReceiveChannel,
) -> Result<(), imp::Error> {
    let client = client.imp();
    client.rt.block_on(
        client
            .inner
            .aqc()
            .ok_or(imp::Error::NotEnabled)?
            .delete_receive_uni_channel(&mut channel.inner),
    )?;
    Ok(())
}

/// Tries to poll AQC to see if any channels have been received.
///
/// This can return `ARANYA_ERROR_WOULD_BLOCK` to signal that there aren't any
/// channels received yet which is considered a non-fatal error.
///
/// Note that the [`AqcPeerChannel`] must be converted before it can be used:
/// ```C
/// AranyaAqcPeerChannel channel;
/// AranyaAqcChannelType channel_type;
/// AranyaAqcBidiChannel bidi;
/// AranyaAqcReceiveChannel receiver;
///
/// aranya_aqc_try_receive_channel(&client, &channel, &channel_type);
/// switch (channel_type) {
///     case ARANYA_AQC_CHANNEL_TYPE_BIDIRECTIONAL:
///         aranya_aqc_get_bidi_channel(&channel, &bidi);
///         break;
///     case ARANYA_AQC_CHANNEL_TYPE_RECEIVER:
///         aranya_aqc_get_receive_channel(&channel, &receiver);
///         break;
/// }
/// ```
///
/// @param[in]  client the Aranya Client [`Client`].
/// @param[out] channel the AQC channel holder [`AqcPeerChannel`].
/// @param[out] __output the corresponding AQC channel type [`AqcChannelType`].
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_try_receive_channel(
    client: &Client,
    channel: &mut MaybeUninit<AqcPeerChannel>,
) -> Result<AqcChannelType, imp::Error> {
    let chan = client
        .inner
        .aqc()
        .ok_or(imp::Error::NotEnabled)?
        .try_receive_channel()?;

    let chan_type = match chan {
        aqc::AqcPeerChannel::Bidi { .. } => AqcChannelType::Bidirectional,
        aqc::AqcPeerChannel::Receive { .. } => AqcChannelType::Receiver,
    };

    AqcPeerChannel::init(channel, imp::AqcPeerChannel::new(chan));

    Ok(chan_type)
}

/// Converts the [`AqcPeerChannel`]` into an [`AqcBidiChannel`] for sending/receiving data.
///
/// Returns `ARANYA_ERROR_INVALID_ARGUMENT` if called when the AqcPeerChannel is the wrong type.
///
/// Note that this function takes ownership of the [`AqcPeerChannel`] and invalidates any further use.
///
/// @param[in]  channel the AQC channel holder [`AqcPeerChannel`] that holds a channel object.
/// @param[out] bidi the AQC channel object [`AqcBidiChannel`] that holds channel info.
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_get_bidi_channel(
    channel: OwnedPtr<AqcPeerChannel>,
    bidi: &mut MaybeUninit<AqcBidiChannel>,
) -> Result<(), imp::Error> {
    if let aqc::AqcPeerChannel::Bidi(channel) =
        // SAFETY: the user is responsible for passing in a valid AqcPeerChannel pointer.
        unsafe { Opaque::into_inner(channel.read()).into_inner().inner }
    {
        AqcBidiChannel::init(bidi, imp::AqcBidiChannel::new(channel));
        Ok(())
    } else {
        Err(InvalidArg::new(
            "channel",
            "Tried to call get_bidi_channel with a `AqcPeerChannel` that wasn't Bidirectional!",
        )
        .into())
    }
}

/// Converts the [`AqcPeerChannel`]` into an [`AqcReceiveChannel`] for receiving data.
///
/// Returns `ARANYA_ERROR_INVALID_ARGUMENT` if called when the AqcPeerChannel is the wrong type.
///
/// Note that this function takes ownership of the [`AqcPeerChannel`] and invalidates any further use.
///
/// @param[in]  channel the AQC channel container [`AqcPeerChannel`].
/// @param[out] receiver the AQC channel object [`AqcReceiveChannel`].
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_get_receive_channel(
    channel: OwnedPtr<AqcPeerChannel>,
    receiver: &mut MaybeUninit<AqcReceiveChannel>,
) -> Result<(), imp::Error> {
    if let aqc::AqcPeerChannel::Receive(recv) =
        // SAFETY: the user is responsible for passing in a valid AqcPeerChannel pointer.
        unsafe { Opaque::into_inner(channel.read()).into_inner().inner }
    {
        AqcReceiveChannel::init(receiver, imp::AqcReceiveChannel::new(recv));
        Ok(())
    } else {
        Err(InvalidArg::new(
            "channel",
            "Tried to call get_receiver_channel with a `AqcPeerChannel` that wasn't a receiver!",
        )
        .into())
    }
}

/// Create a bidirectional stream from a [`AqcBidiChannel`].
///
/// Note that the recipient will not be able to receive the stream until data is
/// sent over the stream.
///
/// @param[in]  client the Aranya Client [`Client`].
/// @param[in]  channel the AQC channel object [`AqcBidiChannel`].
/// @param[out] stream the bidirectional AQC stream [`AqcBidiStream`].
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_bidi_create_bidi_stream(
    client: &Client,
    channel: &mut AqcBidiChannel,
    stream: &mut MaybeUninit<AqcBidiStream>,
) -> Result<(), imp::Error> {
    let bidi = client.rt.block_on(channel.inner.create_bidi_stream())?;

    AqcBidiStream::init(stream, imp::AqcBidiStream::new(bidi));
    Ok(())
}

/// Send some data to a peer using an [`AqcBidiStream`].
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] stream the sending side of a stream [`AqcBidiStream`].
/// @param[in] data pointer to the data to send.
/// @param[in] data_len length of the data to send.
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_bidi_stream_send(
    client: &Client,
    stream: &mut AqcBidiStream,
    data: &[u8],
) -> Result<(), imp::Error> {
    let data = Bytes::copy_from_slice(data);
    Ok(client.rt.block_on(stream.inner.send(data))?)
}

/// Receive some data from an [`AqcBidiStream`].
///
/// This can return `ARANYA_ERROR_WOULD_BLOCK` to signal that there aren't any streams
/// received yet which is considered a non-fatal error.
///
/// @param[in]  stream the receiving side of a stream [`AqcBidiStream`].
/// @param[out] buffer pointer to the target buffer.
/// @param[in,out] buffer_len length of the target buffer.
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub unsafe fn aqc_bidi_stream_try_recv(
    stream: &mut AqcBidiStream,
    buffer: *mut MaybeUninit<u8>,
    buffer_len: &mut usize,
) -> Result<(), imp::Error> {
    if buffer.is_null() || *buffer_len == 0 {
        return Err(InvalidArg::new(
            "buffer",
            "Tried to call aqc_bidi_stream_try_recv with an empty buffer",
        )
        .into());
    }

    let mut written = 0;
    let mut buf = aranya_capi_core::try_as_mut_slice!(buffer, *buffer_len);
    while !buf.is_empty() {
        written += imp::aqc::consume_bytes(&mut buf, &mut stream.data);
        match stream.inner.try_receive() {
            Ok(data) => stream.data = data,
            Err(_) if written > 0 => break,
            Err(e) => return Err(e.into()),
        }
    }
    *buffer_len = written;
    Ok(())
}

/// Create a unidirectional stream from an [`AqcBidiChannel`].
///
/// Note that the recipient will not be able to receive the stream until data is
/// sent over the stream.
///
/// @param[in]  client the Aranya Client [`Client`].
/// @param[in]  channel the AQC channel object [`AqcBidiChannel`].
/// @param[out] stream the sending side of a stream [`AqcSendStream`].
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_bidi_create_uni_stream(
    client: &Client,
    channel: &mut AqcBidiChannel,
    stream: &mut MaybeUninit<AqcSendStream>,
) -> Result<(), imp::Error> {
    let send = client.rt.block_on(channel.inner.create_uni_stream())?;

    AqcSendStream::init(stream, imp::AqcSendStream::new(send));
    Ok(())
}

/// Tries to receive the receive (and potentially send) ends of a stream.
///
/// This can return `ARANYA_ERROR_WOULD_BLOCK` to signal that there aren't any
/// streams received yet which is considered a non-fatal error.
///
/// Note that the recipient will not be able to receive the stream until data is
/// sent over the stream.
///
/// Additionally, the send stream will only be initialized if `send_init` is true.
///
/// @param[in]  channel the AQC channel object [`AqcBidiChannel`].
/// @param[out] recv_stream the receiving side of a stream [`AqcReceiveStream`].
/// @param[out] send_stream the sending side of a stream [`AqcSendStream`].
/// @param[out] send_init whether or not we received a `send_stream`.
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_bidi_try_receive_stream(
    channel: &mut AqcBidiChannel,
    recv_stream: &mut MaybeUninit<AqcReceiveStream>,
    send_stream: &mut MaybeUninit<AqcSendStream>,
    send_init: &mut MaybeUninit<bool>,
) -> Result<(), imp::Error> {
    let stream = channel.inner.try_receive_stream()?;
    match stream {
        AqcPeerStream::Bidi(bidi) => {
            let (send, recv) = bidi.split();
            AqcReceiveStream::init(recv_stream, imp::AqcReceiveStream::new(recv));
            AqcSendStream::init(send_stream, imp::AqcSendStream::new(send));
            send_init.write(true);
        }
        AqcPeerStream::Receive(recv) => {
            AqcReceiveStream::init(recv_stream, imp::AqcReceiveStream::new(recv));
            send_init.write(false);
        }
    }
    Ok(())
}

/// Create a unidirectional stream from an [`AqcSendChannel`].
///
/// Note that the recipient will not be able to receive the stream until data is
/// sent over the stream.
///
/// @param[in]  client the Aranya Client [`Client`].
/// @param[in]  channel the AQC channel object [`AqcSendChannel`].
/// @param[out] stream the sending side of a stream [`AqcSendStream`].
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_send_create_uni_stream(
    client: &Client,
    channel: &mut AqcSendChannel,
    stream: &mut MaybeUninit<AqcSendStream>,
) -> Result<(), imp::Error> {
    let send = client.rt.block_on(channel.inner.create_uni_stream())?;

    AqcSendStream::init(stream, imp::AqcSendStream::new(send));
    Ok(())
}

/// Receives the stream from an [`AqcReceiveChannel`].
///
/// Note that the recipient will not be able to receive the stream until data is
/// sent over the stream.
///
/// This can return `ARANYA_ERROR_WOULD_BLOCK` to signal that there aren't any streams
/// received yet which is considered a non-fatal error.
///
/// @param[in]  channel the AQC channel object [`AqcReceiveChannel`].
/// @param[out] stream the receiving side of a stream [`AqcReceiveStream`].
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_recv_try_receive_uni_stream(
    channel: &mut AqcReceiveChannel,
    stream: &mut MaybeUninit<AqcReceiveStream>,
) -> Result<(), imp::Error> {
    let recv = channel.inner.try_receive_uni_stream()?;

    AqcReceiveStream::init(stream, imp::AqcReceiveStream::new(recv));
    Ok(())
}

/// Send some data over an [`AqcSendStream`]m.
///
/// @param[in] client the Aranya Client [`Client`].
/// @param[in] stream the sending side of a stream [`AqcSendStream`].
/// @param[in] data pointer to the data to send.
/// @param[in] data_len length of the data to send.
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub fn aqc_send_stream_send(
    client: &Client,
    stream: &mut AqcSendStream,
    data: &[u8],
) -> Result<(), imp::Error> {
    let data = Bytes::copy_from_slice(data);
    Ok(client.rt.block_on(stream.inner.send(data))?)
}

/// Receive some data from an [`AqcReceiveStream`].
///
/// This can return `ARANYA_ERROR_WOULD_BLOCK` to signal that there aren't any streams
/// received yet which is considered a non-fatal error.
///
/// @param[in]  stream the receiving side of a stream [`AqcReceiveStream`].
/// @param[out] buffer pointer to the target buffer.
/// @param[in,out] buffer_len length of the target buffer.
///
/// @relates AranyaClient.
#[cfg(feature = "aqc")]
pub unsafe fn aqc_recv_stream_try_recv(
    stream: &mut AqcReceiveStream,
    buffer: *mut MaybeUninit<u8>,
    buffer_len: &mut usize,
) -> Result<(), imp::Error> {
    if buffer.is_null() || *buffer_len == 0 {
        return Err(InvalidArg::new(
            "buffer",
            "Tried to call aqc_recv_stream_try_recv with an empty buffer",
        )
        .into());
    }

    let mut written = 0;
    let mut buf = aranya_capi_core::try_as_mut_slice!(buffer, *buffer_len);
    while !buf.is_empty() {
        written += imp::aqc::consume_bytes(&mut buf, &mut stream.data);
        match stream.inner.try_receive() {
            Ok(data) => stream.data = data,
            Err(_) if written > 0 => break,
            Err(e) => return Err(e.into()),
        }
    }
    *buffer_len = written;
    Ok(())
}
