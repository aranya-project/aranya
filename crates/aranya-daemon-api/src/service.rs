use core::{error, fmt, hash::Hash, time::Duration};
use std::{io, sync::Arc};

pub use aranya_crypto::tls::CipherSuiteId;
use aranya_crypto::{
    dangerous::spideroak_crypto::hex::Hex,
    default::{DefaultCipherSuite, DefaultEngine},
    id::IdError,
    subtle::{Choice, ConstantTimeEq},
    zeroize::{Zeroize, ZeroizeOnDrop},
    EncryptionPublicKey, Engine, Rng,
};
use aranya_id::custom_id;
pub use aranya_policy_text::{text, InvalidText, Text};
use aranya_util::{error::ReportExt, Addr};
use buggy::Bug;
pub use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::{net::UnixStream, sync::Mutex};

pub mod afc;
pub mod quic_sync;

#[cfg(feature = "afc")]
pub use self::afc::*;
pub use self::quic_sync::*;
use super::crypto::txp;

/// CE = Crypto Engine
pub type CE = DefaultEngine;
/// CS = Cipher Suite
pub type CS = <DefaultEngine as Engine>::CS;

/// An error returned by the API.
// TODO: enum?
#[derive(Serialize, Deserialize, Debug)]
pub struct Error(String);

impl Error {
    pub fn from_msg(err: &str) -> Self {
        Self(err.into())
    }

    pub fn from_err<E: error::Error>(err: E) -> Self {
        Self(ReportExt::report(&err).to_string())
    }
}

impl From<Bug> for Error {
    fn from(err: Bug) -> Self {
        Self::from_err(err)
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Self(format!("{err:?}"))
    }
}

impl From<InvalidText> for Error {
    fn from(err: InvalidText) -> Self {
        Self(format!("{err:?}"))
    }
}

impl From<semver::Error> for Error {
    fn from(err: semver::Error) -> Self {
        Self::from_err(err)
    }
}

impl From<IdError> for Error {
    fn from(err: IdError) -> Self {
        Self::from_err(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl error::Error for Error {}

pub type Result<T, E = Error> = core::result::Result<T, E>;

custom_id! {
    /// The Device ID.
    pub struct DeviceId;
}

custom_id! {
    /// The Team ID (a.k.a Graph ID).
    pub struct TeamId;
}

custom_id! {
    /// A label ID.
    pub struct LabelId;
}

custom_id! {
    /// A role ID.
    pub struct RoleId;
}

custom_id! {
    /// An identifier for any object with a unique Aranya ID defined in the policy.
    pub struct ObjectId;
}

/// A numerical rank used for authorization in the rank-based hierarchy.
///
/// Higher-ranked objects can operate on lower-ranked objects.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Rank(i64);

impl Rank {
    /// Creates a new rank from a raw value.
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Returns the raw rank value.
    pub const fn value(self) -> i64 {
        self.0
    }
}

impl fmt::Display for Rank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<i64> for Rank {
    fn from(value: i64) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Role {
    /// Uniquely identifies the role.
    pub id: RoleId,
    /// The role's friendly name.
    pub name: Text,
    /// The author of the role.
    pub author_id: DeviceId,
    /// Is this a default role?
    pub default: bool,
}

/// A device's public key bundle.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PublicKeyBundle {
    pub identity: Vec<u8>,
    pub signing: Vec<u8>,
    pub encryption: Vec<u8>,
}

impl fmt::Debug for PublicKeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeyBundle")
            .field("identity", &Hex::new(&*self.identity))
            .field("signing", &Hex::new(&*self.signing))
            .field("encryption", &Hex::new(&*self.encryption))
            .finish()
    }
}

// Note: any fields added to this type should be public
/// A configuration for adding a team in the daemon.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddTeamConfig {
    pub team_id: TeamId,
    pub quic_sync: Option<AddTeamQuicSyncConfig>,
}

// Note: any fields added to this type should be public
/// A configuration for creating a team in the daemon.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTeamConfig {
    pub quic_sync: Option<CreateTeamQuicSyncConfig>,
}

/// A label.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Label {
    pub id: LabelId,
    pub name: Text,
    pub author_id: DeviceId,
}

/// A PSK IKM.
#[derive(Clone, Serialize, Deserialize)]
pub struct Ikm([u8; SEED_IKM_SIZE]);

impl Ikm {
    /// Provides access to the raw IKM bytes.
    #[inline]
    pub fn raw_ikm_bytes(&self) -> &[u8; SEED_IKM_SIZE] {
        &self.0
    }
}

impl From<[u8; SEED_IKM_SIZE]> for Ikm {
    fn from(value: [u8; SEED_IKM_SIZE]) -> Self {
        Self(value)
    }
}

impl ConstantTimeEq for Ikm {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ZeroizeOnDrop for Ikm {}
impl Drop for Ikm {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl fmt::Debug for Ikm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikm").finish_non_exhaustive()
    }
}

/// A secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct Secret(Box<[u8]>);

impl Secret {
    /// Provides access to the raw secret bytes.
    #[inline]
    pub fn raw_secret_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<T> From<T> for Secret
where
    T: Into<Box<[u8]>>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl ConstantTimeEq for Secret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ZeroizeOnDrop for Secret {}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret").finish_non_exhaustive()
    }
}

/// Configuration values for syncing with a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncPeerConfig {
    /// The interval at which syncing occurs. If None, the peer will not be periodically synced.
    pub interval: Option<Duration>,
    /// Determines whether the peer will be scheduled for an immediate sync when added.
    pub sync_now: bool,
    /// Determines if the peer should be synced with when a hello message is received
    /// indicating they have a head that we don't have
    #[cfg(feature = "preview")]
    pub sync_on_hello: bool,
}

/// Valid channel operations for a label assignment.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
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

/// Permissions that can be granted to a role.
///
/// # Stability
///
/// New permissions may be added to the end of this enum without breaking
/// backward compatibility. Existing permissions will not be removed or
/// renamed.
///
/// # Deprecation
///
/// Deprecated variants are marked with `#[deprecated]` and will emit
/// compiler warnings when used. They remain in the enum for backward
/// compatibility — see the deprecation note on each variant for the
/// migration path.
// This enum is re-exported as `aranya_client::Permission`. New
// permissions may be added as the policy evolves, so `non_exhaustive`
// ensures downstream match statements continue to compile.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Perm {
    // # Team management
    //
    // The role can add a device to the team.
    AddDevice,
    // The role can remove a device from the team.
    RemoveDevice,
    // The role can terminate the team.
    TerminateTeam,

    // # Rank
    //
    // The role can change the rank of objects.
    ChangeRank,

    // # Roles
    //
    // The role can create a role.
    CreateRole,
    // The role can delete a role.
    DeleteRole,
    // The role can assign a role to other devices.
    AssignRole,
    // The role can revoke a role from other devices.
    RevokeRole,
    // The role can change permissions on roles.
    ChangeRolePerms,
    // The role can set up default roles.
    SetupDefaultRole,

    // # Labels
    //
    // The role can create a label.
    CreateLabel,
    // The role can delete a label.
    DeleteLabel,
    // The role can assign a label to a device.
    AssignLabel,
    // The role can revoke a label from a device.
    RevokeLabel,

    // # AFC
    //
    // The role can use AFC.
    CanUseAfc,
    // The role can create a unidirectional AFC channel.
    CreateAfcUniChannel,
}

/// Errors from the client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Transport/IO failure
    #[error("transport error: {0}")]
    Transport(#[from] io::Error),
    /// The server returned an API error.
    #[error("api error: {0}")]
    Api(#[from] Error),
    /// Response didn't match the request we sent.
    #[error("unexpected response from daemon")]
    WrongResponse,
}

/// RPC client wrapping an encrypted conection.
#[derive(Debug, Clone)]
pub struct DaemonApiClient {
    conn: Arc<Mutex<ClientConn>>,
}

type ClientConn = txp::ClientConn<UnixStream, Rng, DefaultCipherSuite>;

impl DaemonApiClient {
    /// Creates a new `DaemonApiClient`.
    pub fn new(conn: ClientConn) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    /// Sends a request to the daemon and waits for a response.
    async fn call(&self, req: DaemonApiRequest) -> Result<DaemonApiResponse, ClientError> {
        let mut conn = self.conn.lock().await;
        conn.send(req).await?;
        conn.recv()
            .await
            .map_err(ClientError::Transport)?
            .ok_or_else(|| {
                ClientError::Transport(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "daemon closed connection",
                ))
            })
    }
}

macro_rules! rpc {
    ($(
        $(#[$meta:meta])*
        fn $name:ident($($arg:ident : $ty:ty),* $(,)?) -> $ret:ty;
    )*) => {
        /// All possible expected requests to the daemon.
        #[derive(Debug, Serialize, Deserialize)]
        #[allow(non_camel_case_types)]
        pub enum DaemonApiRequest {
            $(
                $(#[$meta])*
                $name { $($arg: $ty),* },
            )*
        }

        /// All possible expected responses from the daemon.
        #[derive(Debug, Serialize, Deserialize)]
        #[allow(non_camel_case_types)]
        pub enum DaemonApiResponse {
            UnknownRequest,
            $(
                $(#[$meta])*
                $name(Result<$ret>),
            )*
        }

        /// The handler trait, needs to be implemented server-side.
        #[allow(unused_variables, async_fn_in_trait)]
        pub trait DaemonApi {
            $(
                $(#[$meta])*
                async fn $name(&self, $($arg: $ty),*) -> Result<$ret>;
            )*

            async fn dispatch(&self, req: DaemonApiRequest) -> DaemonApiResponse {
                #[allow(unused_doc_comments)]
                match req {
                    $(
                        $(#[$meta])*
                        DaemonApiRequest::$name { $($arg),* } => {
                            DaemonApiResponse::$name(self.$name($($arg),*).await)
                        }
                    )*
                    // cfg'd-out variants need a catch-all
                    #[allow(unreachable_patterns)]
                    _ => DaemonApiResponse::UnknownRequest,
                }
            }
        }

        // Client stub, each method sends a `Request` and expects the matching `Response` variant.
        impl DaemonApiClient {
            $(
                $(#[$meta])*
                pub async fn $name(&self, $($arg: $ty),*) -> Result<$ret, ClientError> {
                    let resp = self.call(DaemonApiRequest::$name { $($arg),* }).await?;
                    match resp {
                        DaemonApiResponse::$name(r) => r.map_err(ClientError::Api),
                        _ => Err(ClientError::WrongResponse),
                    }
                }
            )*
        }
    };
}

rpc! {
    /* Miscellaneous */
    /// Returns the daemon's version.
    fn version() -> Version;
    /// Gets local address the Aranya sync server is bound to.
    fn aranya_local_addr() -> Addr;

    /// Gets the public key bundle for this device
    fn get_public_key_bundle() -> PublicKeyBundle;
    /// Gets the public device id.
    fn get_device_id() -> DeviceId;

    /* Syncing */
    /// Adds the peer for automatic periodic syncing.
    fn add_sync_peer(addr: Addr, team: TeamId, config: SyncPeerConfig) -> ();
    /// Removes the peer from automatic syncing.
    fn remove_sync_peer(addr: Addr, team: TeamId) -> ();
    /// Sync with peer immediately.
    fn sync_now(addr: Addr, team: TeamId, cfg: Option<SyncPeerConfig>) -> ();

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    fn sync_hello_subscribe(
        peer: Addr,
        team: TeamId,
        graph_change_debounce: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> ();
    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    fn sync_hello_unsubscribe(peer: Addr, team: TeamId) -> ();

    /// add a team to the local device store that was created elsewhere. Not an aranya action/command.
    fn add_team(cfg: AddTeamConfig) -> ();
    /// Remove a team from local device storage.
    fn remove_team(team: TeamId) -> ();
    /// Create a new graph/team with the current device as the owner.
    fn create_team(cfg: CreateTeamConfig) -> TeamId;
    /// Close the team.
    fn close_team(team: TeamId) -> ();

    /// Encrypts the team's syncing PSK(s) for the peer.
    fn encrypt_psk_seed_for_peer(team: TeamId, peer_enc_pk: EncryptionPublicKey<CS>)
        -> WrappedSeed;

    /* Device Onboarding */
    /// Adds a device to the team with an optional initial role and explicit rank.
    fn add_device_to_team(
        team: TeamId,
        keys: PublicKeyBundle,
        initial_role: Option<RoleId>,
        rank: Rank,
    ) -> ();
    /// Remove device from the team.
    fn remove_device_from_team(team: TeamId, device: DeviceId) -> ();
    /// Returns all the devices on the team.
    fn devices_on_team(team: TeamId) -> Box<[DeviceId]>;
    /// Returns the device's public key bundle.
    fn device_public_key_bundle(team: TeamId, device: DeviceId) -> PublicKeyBundle;

    /* Role Creation */
    /// Configures the team with default roles from policy.
    ///
    /// It returns the default roles that were created.
    fn setup_default_roles(team: TeamId) -> Box<[Role]>;
    /// Creates a new role with the given rank.
    fn create_role(team: TeamId, role_name: Text, rank: Rank) -> Role;
    /// Deletes a role.
    fn delete_role(team: TeamId, role_id: RoleId) -> ();
    /// Returns the current team roles.
    fn team_roles(team: TeamId) -> Box<[Role]>;

    /* Role Management */
    /// Adds a permission to a role.
    fn add_perm_to_role(team: TeamId, role: RoleId, perm: Perm) -> ();
    /// Removes a permission from a role.
    fn remove_perm_from_role(team: TeamId, role: RoleId, perm: Perm) -> ();
    /// Queries all permissions assigned to a role.
    fn query_role_perms(team: TeamId, role: RoleId) -> Vec<Perm>;
    /// Changes the rank of an object (device or label).
    ///
    /// Note: Role ranks cannot be changed after creation. This maintains the
    /// invariant that `role_rank > device_rank` for all devices assigned to
    /// the role. To effectively change a role's rank, create a new role with
    /// matching permissions at the desired rank, assign the new role to the
    /// devices that had the old role, then delete the old role.
    fn change_rank(team: TeamId, object_id: ObjectId, old_rank: Rank, new_rank: Rank) -> ();
    /// Queries the rank of an object.
    fn query_rank(team: TeamId, object_id: ObjectId) -> Rank;

    /* Role Assignment */
    /// Assign a role to a device.
    fn assign_role(team: TeamId, device: DeviceId, role: RoleId) -> ();
    /// Revoke a role from a device.
    fn revoke_role(team: TeamId, device: DeviceId, role: RoleId) -> ();
    /// Changes the assigned role of a device.
    fn change_role(team: TeamId, device: DeviceId, old_role: RoleId, new_role: RoleId) -> ();
    /// Returns the role assigned to the device.
    fn device_role(team: TeamId, device: DeviceId) -> Option<Role>;

    /* Label Creation */
    /// Creates a label with an explicit rank.
    fn create_label(team: TeamId, name: Text, rank: Rank) -> LabelId;
    /// Delete a label.
    fn delete_label(team: TeamId, label_id: LabelId) -> ();
    /// Returns a specific label.
    fn label(team: TeamId, label: LabelId) -> Option<Label>;
    /// Returns all labels on the team.
    fn labels(team: TeamId) -> Vec<Label>;

    /* Label Assignments */
    /// Assigns a label to a device.
    fn assign_label_to_device(team: TeamId, device: DeviceId, label: LabelId, op: ChanOp) -> ();
    /// Revokes a label from a device.
    fn revoke_label_from_device(team: TeamId, device: DeviceId, label: LabelId) -> ();
    /// Returns all labels assigned to the device.
    fn labels_assigned_to_device(team: TeamId, device: DeviceId) -> Box<[Label]>;

    /* AFC Options */
    /// Gets AFC shared-memory configuration info.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    fn afc_shm_info() -> AfcShmInfo;
    /// Create a send-only AFC channel.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    fn create_afc_channel(team: TeamId, peer_id: DeviceId, label_id: LabelId)
        -> AfcSendChannelInfo;
    /// Delete a AFC channel.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    fn delete_afc_channel(chan: AfcLocalChannelId) -> ();
    /// Accept a receive-only AFC channel by processing a peer's ctrl message.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    fn accept_afc_channel(team: TeamId, ctrl: AfcCtrl) -> AfcReceiveChannelInfo;
}
