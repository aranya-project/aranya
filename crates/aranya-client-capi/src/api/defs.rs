use core::{ffi::c_char, ops::DerefMut, ptr, slice};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
use std::ffi::CString;
use aranya_capi_core::{prelude::*, ErrorCode, InvalidArg};
use libc;
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
                aranya_client::Error::Afc(_) => Self::Afc,
                aranya_client::Error::Bug(_) => Self::Bug,
            },
            imp::Error::Runtime(_) => Self::Runtime,
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

/// Team ID.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 64, align = 1)]
pub struct TeamId(aranya_daemon_api::TeamId);

/// Device ID.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 64, align = 1)]
pub struct DeviceId(aranya_daemon_api::DeviceId);

/// Channel ID for a fast channel.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 16, align = 1)]
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
    // TODO: not sure if this is right.
    fn from_underlying(net_identifier: aranya_daemon_api::NetIdentifier) -> Self {
        let cstr = CString::new(net_identifier.0.as_str()).expect("expected valid C str");
        NetIdentifier(cstr.as_c_str().as_ptr())
    }
}

/// An AFC label.
///
/// It identifies the policy rules that govern the AFC channel.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct Label(u32);

impl From<Label> for aranya_fast_channels::Label {
    fn from(value: Label) -> Self {
        Self::new(value.0)
    }
}

impl From<aranya_fast_channels::Label> for Label {
    fn from(value: aranya_fast_channels::Label) -> Self {
        Self(value.to_u32())
    }
}

/// A type to represent a span of time.
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

/// Aranya client configuration.
#[repr(C)]
#[must_use]
#[derive(Copy, Clone, Debug)]
pub struct ClientConfig {
    /// Daemon API unix domain socket path.
    pub daemon_sock: *const c_char,
    /// Aranya Fast Channels (AFC) config.
    pub afc: AfcConfig,
}

/// Aranya Fast Channels (AFC) config.
#[repr(C)]
#[must_use]
#[derive(Copy, Clone, Debug)]
pub struct AfcConfig {
    /// Shared memory path.
    pub shm_path: *const c_char,
    /// Maximum number of channels to store in shared-memory.
    pub max_channels: usize,
    /// Address to bind AFC server to.
    pub addr: *const c_char,
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
    // TODO: builder?
    // TODO: Clean this up.
    let daemon_sock = OsStr::from_bytes(
        // SAFETY: Caller must ensure pointer is a valid C String.
        unsafe { std::ffi::CStr::from_ptr(config.daemon_sock) }.to_bytes(),
    )
    .as_ref();
    let afc_shm_path = OsStr::from_bytes(
        // SAFETY: Caller must ensure pointer is a valid C String.
        unsafe { std::ffi::CStr::from_ptr(config.afc.shm_path) }.to_bytes(),
    )
    .as_ref();
    let afc_addr =
        // SAFETY: Caller must ensure pointer is a valid C String.
        unsafe { std::ffi::CStr::from_ptr(config.afc.addr) }
        .to_str()?;
    let rt = tokio::runtime::Runtime::new().map_err(imp::Error::Runtime)?;
    let inner = rt.block_on(aranya_client::Client::connect(
        daemon_sock,
        afc_shm_path,
        config.afc.max_channels,
        afc_addr,
    ))?;
    Safe::init(
        client,
        imp::Client {
            rt,
            inner,
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
    Ok(DeviceId(id))
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
    Ok(TeamId(id))
}

/// Add a team to the local device store.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
///
/// @relates AranyaClient.
pub fn add_team(client: &mut Client, team: &TeamId) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(client.inner.add_team(team.0))?;
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
    client.rt.block_on(client.inner.remove_team(team.0))?;
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
/// @param interval the time [`Duration`] to wait between syncs with peer.
///
/// @relates AranyaClient.
pub unsafe fn add_sync_peer(
    client: &mut Client,
    team: &TeamId,
    addr: Addr,
    interval: Duration,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `addr` is a valid C String.
    let addr = unsafe { addr.as_underlying() }?;
    client.rt.block_on(
        client
            .inner
            .team(team.0)
            .add_sync_peer(addr, interval.into()),
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
        .block_on(client.inner.team(team.0).remove_sync_peer(addr))?;
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
    client.rt.block_on(client.inner.team(team.0).close_team())?;
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
        .block_on(client.inner.team(team.0).add_device_to_team(keys))?;
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
    client
        .rt
        .block_on(client.inner.team(team.0).remove_device_from_team(device.0))?;
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
    client
        .rt
        .block_on(client.inner.team(team.0).assign_role(device.0, role.into()))?;
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
    client
        .rt
        .block_on(client.inner.team(team.0).revoke_role(device.0, role.into()))?;
    Ok(())
}

/// Associate a network identifier to a device for use with AFC.
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
            .team(team.0)
            .assign_afc_net_identifier(device.0, net_identifier),
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
            .team(team.0)
            .remove_afc_net_identifier(device.0, net_identifier),
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
            .team(team.0)
            .assign_aqc_net_identifier(device.0, net_identifier),
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
            .team(team.0)
            .remove_aqc_net_identifier(device.0, net_identifier),
    )?;
    Ok(())
}

/// Create a channel label.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param label the AFC channel label [`Label`] to create.
///
/// @relates AranyaClient.
pub fn create_label(client: &mut Client, team: &TeamId, label: Label) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.team(team.0).create_label(label.into()))?;
    Ok(())
}

/// Delete a channel label.
///
/// Permission to perform this operation is checked against the Aranya policy.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param label the channel label [`Label`] to delete.
///
/// @relates AranyaClient.
pub fn delete_label(client: &mut Client, team: &TeamId, label: Label) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.team(team.0).delete_label(label.into()))?;
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
pub fn assign_label(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    label: Label,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.0)
            .assign_label(device.0, label.into()),
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
pub fn revoke_label(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
    label: Label,
) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(
        client
            .inner
            .team(team.0)
            .revoke_label(device.0, label.into()),
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
pub unsafe fn afc_create_bidi_channel(
    client: &mut Client,
    team: &TeamId,
    peer: NetIdentifier,
    label: Label,
) -> Result<ChannelId, imp::Error> {
    let client = client.deref_mut();
    // SAFETY: Caller must ensure `peer` is a valid C String.
    let peer = unsafe { peer.as_underlying() }?;
    let id = client.rt.block_on(client.inner.create_afc_bidi_channel(
        team.0,
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
pub fn afc_delete_channel(client: &mut Client, chan: ChannelId) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.delete_afc_channel(chan.0))?;
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
pub fn afc_poll_data(client: &mut Client, timeout: Duration) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client.rt.block_on(async {
        let data = tokio::time::timeout(timeout.into(), client.inner.poll_afc_data()).await??;
        client.inner.handle_afc_data(data).await?;
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
pub fn afc_send_data(client: &mut Client, chan: ChannelId, data: &[u8]) -> Result<(), imp::Error> {
    let client = client.deref_mut();
    client
        .rt
        .block_on(client.inner.send_afc_data(chan.0, data))?;
    Ok(())
}

/// Aranya Fast Channels (AFC) message info.
#[repr(C)]
#[derive(Debug)]
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
pub struct SocketAddr(
    /// libc Socket address.
    // TODO: Custom type instead?
    pub  libc::sockaddr_storage,
);

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
pub unsafe fn afc_recv_data(
    client: &mut Client,
    buf: Writer<u8>,
    info: &mut MaybeUninit<AfcMsgInfo>,
) -> Result<bool, imp::Error> {
    let client = client.deref_mut();

    if client.msg.is_none() {
        client.msg = client.inner.try_recv_afc_data();
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
        addr: msg.addr.into(),
    });

    client.msg = None;

    Ok(true)
}

// TODO: query_devices_on_team

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
            .team(team.0)
            .query_device_keybundle(device.0),
    )?;
    Ok(KeyBundle::from_underlying(keys))
}

// TODO: query_device_label_assignments

/// Query device's AFC network identifier.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param __output the device's network identifier [`NetIdentifier`].
/// 
/// @relates AranyaClient.
pub unsafe fn query_afc_net_identifier(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
) -> Result<NetIdentifier, imp::Error> {
    let client = client.deref_mut();
    let net_identifier = client.rt.block_on(
        client
            .inner
            .team(team.0)
            .query_afc_net_identifier(device.0),
    )?;
    Ok(NetIdentifier::from_underlying(net_identifier))
}

/// Query device's AQC network identifier.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param __output the device's network identifier [`NetIdentifier`].
/// 
/// @relates AranyaClient.
pub unsafe fn query_aqc_net_identifier(
    client: &mut Client,
    team: &TeamId,
    device: &DeviceId,
) -> Result<NetIdentifier, imp::Error> {
    let client = client.deref_mut();
    let net_identifier = client.rt.block_on(
        client
            .inner
            .team(team.0)
            .query_aqc_net_identifier(device.0),
    )?;
    Ok(NetIdentifier::from_underlying(net_identifier))
}

/// Query device's AQC network identifier.
///
/// @param client the Aranya Client [`Client`].
/// @param team the team's ID [`TeamId`].
/// @param device the device's ID [`DeviceId`].
/// @param __output the device's network identifier [`NetIdentifier`].
/// 
/// @relates AranyaClient.
pub unsafe fn query_label_exists(
    client: &mut Client,
    team: &TeamId,
    label: &Label,
) -> Result<bool, imp::Error> {
    let client = client.deref_mut();
    let exists = client.rt.block_on(
        client
            .inner
            .team(team.0)
            .query_label_exists(label.0.into()),
    )?;
    Ok(exists)
}
