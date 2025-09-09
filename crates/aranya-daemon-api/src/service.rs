#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::{
    borrow::Borrow,
    error, fmt,
    hash::{Hash, Hasher},
    net::SocketAddr,
    ops::Deref,
    time::Duration,
};
use std::collections::hash_map::{self, HashMap};

use anyhow::bail;
pub use aranya_crypto::aqc::CipherSuiteId;
use aranya_crypto::{
    aqc::{BidiPskId, UniPskId},
    custom_id,
    default::DefaultEngine,
    id::IdError,
    subtle::{Choice, ConstantTimeEq},
    zeroize::{Zeroize, ZeroizeOnDrop},
    EncryptionPublicKey, Engine, Id,
};
pub use aranya_fast_channels::ChannelId as AfcChannelId;
pub use aranya_policy_text::{text, Text};
use aranya_util::{error::ReportExt, Addr, ShmPathBuf};
use buggy::Bug;
pub use semver::Version;
use serde::{Deserialize, Serialize};

pub mod quic_sync;
pub use quic_sync::*;

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
    /// An AQC label ID.
    pub struct LabelId;
}

custom_id! {
    /// An AQC bidi channel ID.
    pub struct AqcBidiChannelId;
}

custom_id! {
    /// An AQC uni channel ID.
    pub struct AqcUniChannelId;
}

/// A device's public key bundle.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct KeyBundle {
    pub identity: Vec<u8>,
    pub signing: Vec<u8>,
    pub encoding: Vec<u8>,
}

/// A device's role on the team.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum Role {
    Owner,
    Admin,
    Operator,
    Member,
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

/// A device's network identifier.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetIdentifier(pub Text);

impl Borrow<str> for NetIdentifier {
    #[inline]
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl<T> AsRef<T> for NetIdentifier
where
    T: ?Sized,
    <Self as Deref>::Target: AsRef<T>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

impl Deref for NetIdentifier {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for NetIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A serialized command for AQC.
pub type AqcCtrl = Vec<Box<[u8]>>;

/// A serialized command for AFC.
pub type AfcCtrl = Vec<Box<[u8]>>;

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

macro_rules! psk_map {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident(PskMap<$psk:ty>);
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq))]
        $vis struct $name {
            id: Id,
            psks: HashMap<CsId, $psk>
        }

        impl $name {
            /// Returns the number of PSKs.
            pub fn len(&self) -> usize {
                self.psks.len()
            }

            /// Reports whether `self` is empty.
            pub fn is_empty(&self) -> bool {
                self.psks.is_empty()
            }

            /// Returns the channel ID.
            pub fn channel_id(&self) -> &Id {
                &self.id
            }

            /// Returns the PSK for the cipher suite.
            pub fn get(&self, suite: CipherSuiteId) -> Option<&$psk> {
                self.psks.get(&CsId(suite))
            }

            /// Creates a PSK map from a function that generates
            /// a PSK for a cipher suite.
            pub fn try_from_fn<I, E, F>(id: I, mut f: F) -> anyhow::Result<Self>
            where
                I: Into<Id>,
                anyhow::Error: From<E>,
                F: FnMut(CipherSuiteId) -> Result<$psk, E>,
            {
                let id = id.into();
                let mut psks = HashMap::new();
                for &suite in CipherSuiteId::all() {
                    let psk = f(suite)?;
                    if !bool::from(psk.identity().channel_id().into_id().ct_eq(&id)) {
                        bail!("PSK identity does not match channel ID");
                    }
                    psks.insert(CsId(suite), psk);
                }
                Ok(Self { id, psks })
            }
        }

        impl IntoIterator for $name {
            type Item = (CipherSuiteId, $psk);
            type IntoIter = IntoPsks<$psk>;

            fn into_iter(self) -> Self::IntoIter {
                IntoPsks {
                    iter: self.psks.into_iter(),
                }
            }
        }

        #[cfg(test)]
        impl tests::PskMap for $name {
            type Psk = $psk;

            fn new() -> Self {
                Self {
                    // TODO
                    id: Id::default(),
                    psks: HashMap::new(),
                }
            }

            fn len(&self) -> usize {
                self.psks.len()
            }

            fn insert(&mut self, psk: Self::Psk) {
                let suite = psk.cipher_suite();
                let opt = self.psks.insert(CsId(suite), psk);
                assert!(opt.is_none());
            }
        }
    };
}
psk_map! {
    /// An injective mapping of PSKs to cipher suites for
    /// a single bidirectional channel.
    pub struct AqcBidiPsks(PskMap<AqcBidiPsk>);
}

psk_map! {
    /// An injective mapping of PSKs to cipher suites for
    /// a single unidirectional channel.
    pub struct AqcUniPsks(PskMap<AqcUniPsk>);
}

/// An injective mapping of PSKs to cipher suites for a single
/// bidirectional or unidirectional channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AqcPsks {
    Bidi(AqcBidiPsks),
    Uni(AqcUniPsks),
}

impl IntoIterator for AqcPsks {
    type IntoIter = AqcPsksIntoIter;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            AqcPsks::Bidi(psks) => AqcPsksIntoIter::Bidi(psks.into_iter()),
            AqcPsks::Uni(psks) => AqcPsksIntoIter::Uni(psks.into_iter()),
        }
    }
}

/// An iterator over an AQC channel's PSKs.
#[derive(Debug)]
pub enum AqcPsksIntoIter {
    Bidi(IntoPsks<AqcBidiPsk>),
    Uni(IntoPsks<AqcUniPsk>),
}

impl Iterator for AqcPsksIntoIter {
    type Item = (CipherSuiteId, AqcPsk);
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            AqcPsksIntoIter::Bidi(it) => it.next().map(|(s, k)| (s, AqcPsk::Bidi(k))),
            AqcPsksIntoIter::Uni(it) => it.next().map(|(s, k)| (s, AqcPsk::Uni(k))),
        }
    }
}

/// An iterator over an AQC channel's PSKs.
#[derive(Debug)]
pub struct IntoPsks<V> {
    iter: hash_map::IntoIter<CsId, V>,
}

impl<V> Iterator for IntoPsks<V> {
    type Item = (CipherSuiteId, V);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(k, v)| (k.0, v))
    }
}

// TODO(eric): Get rid of this once `CipherSuiteId` implements
// `Hash`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
struct CsId(CipherSuiteId);

impl Hash for CsId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

/// An AQC PSK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AqcPsk {
    /// Bidirectional.
    Bidi(AqcBidiPsk),
    /// Unidirectional.
    Uni(AqcUniPsk),
}

impl AqcPsk {
    /// Returns the PSK identity.
    #[inline]
    pub fn identity(&self) -> AqcPskId {
        match self {
            Self::Bidi(psk) => AqcPskId::Bidi(psk.identity),
            Self::Uni(psk) => AqcPskId::Uni(psk.identity),
        }
    }

    /// Returns the PSK cipher suite.
    #[inline]
    pub fn cipher_suite(&self) -> CipherSuiteId {
        self.identity().cipher_suite()
    }

    /// Returns the PSK secret.
    #[inline]
    pub fn secret(&self) -> &[u8] {
        match self {
            Self::Bidi(psk) => psk.secret.raw_secret_bytes(),
            Self::Uni(psk) => match &psk.secret {
                Directed::Send(secret) | Directed::Recv(secret) => secret.raw_secret_bytes(),
            },
        }
    }
}

impl From<AqcBidiPsk> for AqcPsk {
    fn from(psk: AqcBidiPsk) -> Self {
        Self::Bidi(psk)
    }
}

impl From<AqcUniPsk> for AqcPsk {
    fn from(psk: AqcUniPsk) -> Self {
        Self::Uni(psk)
    }
}

impl ConstantTimeEq for AqcPsk {
    fn ct_eq(&self, other: &Self) -> Choice {
        // It's fine that matching discriminants isn't constant
        // time since it isn't secret data.
        match (self, other) {
            (Self::Bidi(lhs), Self::Bidi(rhs)) => lhs.ct_eq(rhs),
            (Self::Uni(lhs), Self::Uni(rhs)) => lhs.ct_eq(rhs),
            _ => Choice::from(0u8),
        }
    }
}

/// An AQC bidirectional channel PSK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AqcBidiPsk {
    /// The PSK identity.
    pub identity: BidiPskId,
    /// The PSK's secret.
    pub secret: Secret,
}

impl AqcBidiPsk {
    fn identity(&self) -> &BidiPskId {
        &self.identity
    }

    #[cfg(test)]
    fn cipher_suite(&self) -> CipherSuiteId {
        self.identity.cipher_suite()
    }
}

impl ConstantTimeEq for AqcBidiPsk {
    fn ct_eq(&self, other: &Self) -> Choice {
        let id = self.identity.ct_eq(&other.identity);
        let secret = self.secret.ct_eq(&other.secret);
        id & secret
    }
}

impl ZeroizeOnDrop for AqcBidiPsk {}

/// An AQC unidirectional PSK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AqcUniPsk {
    /// The PSK identity.
    pub identity: UniPskId,
    /// The PSK's secret.
    pub secret: Directed<Secret>,
}

impl AqcUniPsk {
    fn identity(&self) -> &UniPskId {
        &self.identity
    }

    #[cfg(test)]
    fn cipher_suite(&self) -> CipherSuiteId {
        self.identity.cipher_suite()
    }
}

impl ConstantTimeEq for AqcUniPsk {
    fn ct_eq(&self, other: &Self) -> Choice {
        let id = self.identity.ct_eq(&other.identity);
        let secret = self.secret.ct_eq(&other.secret);
        id & secret
    }
}

impl ZeroizeOnDrop for AqcUniPsk {}

/// Either send only or receive only.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Directed<T> {
    /// Send only.
    Send(T),
    /// Receive only.
    Recv(T),
}

impl<T: ConstantTimeEq> ConstantTimeEq for Directed<T> {
    fn ct_eq(&self, other: &Self) -> Choice {
        // It's fine that matching discriminants isn't constant
        // time since the direction isn't secret data.
        match (self, other) {
            (Self::Send(lhs), Self::Send(rhs)) => lhs.ct_eq(rhs),
            (Self::Recv(lhs), Self::Recv(rhs)) => lhs.ct_eq(rhs),
            _ => Choice::from(0u8),
        }
    }
}

/// An AQC PSK identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AqcPskId {
    /// A bidirectional PSK.
    Bidi(BidiPskId),
    /// A unidirectional PSK.
    Uni(UniPskId),
}

impl AqcPskId {
    /// Returns the unique channel ID.
    pub fn channel_id(&self) -> Id {
        match self {
            Self::Bidi(v) => (*v.channel_id()).into(),
            Self::Uni(v) => (*v.channel_id()).into(),
        }
    }

    /// Returns the cipher suite.
    pub fn cipher_suite(&self) -> CipherSuiteId {
        match self {
            Self::Bidi(v) => v.cipher_suite(),
            Self::Uni(v) => v.cipher_suite(),
        }
    }

    /// Converts the ID to its byte encoding.
    pub fn as_bytes(&self) -> &[u8; 34] {
        match self {
            Self::Bidi(v) => v.as_bytes(),
            Self::Uni(v) => v.as_bytes(),
        }
    }
}

/// Configuration values for syncing with a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncPeerConfig {
    /// The interval at which syncing occurs
    pub interval: Duration,
    /// Determines if a peer should be synced with immediately after they're added
    pub sync_now: bool,
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
    /// The device can send and receive data in channels with this
    /// label.
    SendRecv,
}

/// A label.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Label {
    pub id: LabelId,
    pub name: Text,
}

/// AFC shared-memory info.
#[derive(Clone, Debug, Serialize, Deserialize)]

pub struct AfcShmInfo {
    pub path: ShmPathBuf,
    pub max_chans: usize,
}

#[tarpc::service]
pub trait DaemonApi {
    /// Returns the daemon's version.
    async fn version() -> Result<Version>;

    /// Gets local address the Aranya sync server is bound to.
    async fn aranya_local_addr() -> Result<SocketAddr>;

    /// Gets the public key bundle for this device
    async fn get_key_bundle() -> Result<KeyBundle>;

    /// Gets the public device id.
    async fn get_device_id() -> Result<DeviceId>;

    /// Gets AFC shared-memory configuration info.
    async fn afc_shm_info() -> Result<AfcShmInfo>;

    /// Adds the peer for automatic periodic syncing.
    async fn add_sync_peer(addr: Addr, team: TeamId, config: SyncPeerConfig) -> Result<()>;

    /// Sync with peer immediately.
    async fn sync_now(addr: Addr, team: TeamId, cfg: Option<SyncPeerConfig>) -> Result<()>;

    /// Removes the peer from automatic syncing.
    async fn remove_sync_peer(addr: Addr, team: TeamId) -> Result<()>;

    /// add a team to the local device store that was created by someone else. Not an aranya action/command.
    async fn add_team(cfg: AddTeamConfig) -> Result<()>;

    /// Remove a team from local device storage.
    async fn remove_team(team: TeamId) -> Result<()>;

    /// Create a new graph/team with the current device as the owner.
    async fn create_team(cfg: CreateTeamConfig) -> Result<TeamId>;
    /// Close the team.
    async fn close_team(team: TeamId) -> Result<()>;

    async fn encrypt_psk_seed_for_peer(
        team: TeamId,
        peer_enc_pk: EncryptionPublicKey<CS>,
    ) -> Result<WrappedSeed>;

    /// Add device to the team.
    async fn add_device_to_team(team: TeamId, keys: KeyBundle) -> Result<()>;
    /// Remove device from the team.
    async fn remove_device_from_team(team: TeamId, device: DeviceId) -> Result<()>;

    /// Assign a role to a device.
    async fn assign_role(team: TeamId, device: DeviceId, role: Role) -> Result<()>;
    /// Revoke a role from a device.
    async fn revoke_role(team: TeamId, device: DeviceId, role: Role) -> Result<()>;

    // Create a label.
    async fn create_label(team: TeamId, name: Text) -> Result<LabelId>;
    // Delete a label.
    async fn delete_label(team: TeamId, label_id: LabelId) -> Result<()>;
    // Assign a label to a device.
    async fn assign_label(
        team: TeamId,
        device: DeviceId,
        label_id: LabelId,
        op: ChanOp,
    ) -> Result<()>;
    // Revoke a label from a device.
    async fn revoke_label(team: TeamId, device: DeviceId, label_id: LabelId) -> Result<()>;

    /// Assign a QUIC channels network identifier to a device.
    async fn assign_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;
    /// Remove a QUIC channels network identifier from a device.
    async fn remove_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> Result<()>;
    /// Create a bidirectional QUIC channel.
    async fn create_aqc_bidi_channel(
        team: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> Result<(AqcCtrl, AqcBidiPsks)>;
    /// Create a unidirectional QUIC channel.
    async fn create_aqc_uni_channel(
        team: TeamId,
        peer: NetIdentifier,
        label_id: LabelId,
    ) -> Result<(AqcCtrl, AqcUniPsks)>;
    /// Receive AQC ctrl message.
    async fn receive_aqc_ctrl(team: TeamId, ctrl: AqcCtrl) -> Result<(LabelId, AqcPsks)>;

    /// Create a bidirectional AFC channel.
    async fn create_afc_bidi_channel(
        team: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> Result<(AqcCtrl, AfcChannelId)>;
    /// Create a unidirectional AFC channel.
    async fn create_afc_uni_channel(
        team: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> Result<(AqcCtrl, AfcChannelId)>;
    /// Delete a AFC channel.
    async fn delete_afc_channel(chan: AfcChannelId) -> Result<()>;
    /// Receive AFC ctrl message.
    async fn receive_afc_ctrl(team: TeamId, ctrl: AfcCtrl) -> Result<(LabelId, AfcChannelId)>;

    /// Query devices on team.
    async fn query_devices_on_team(team: TeamId) -> Result<Vec<DeviceId>>;
    /// Query device role.
    async fn query_device_role(team: TeamId, device: DeviceId) -> Result<Role>;
    /// Query device keybundle.
    async fn query_device_keybundle(team: TeamId, device: DeviceId) -> Result<KeyBundle>;
    /// Query device label assignments.
    async fn query_device_label_assignments(team: TeamId, device: DeviceId) -> Result<Vec<Label>>;
    /// Query AQC network ID.
    async fn query_aqc_net_identifier(
        team: TeamId,
        device: DeviceId,
    ) -> Result<Option<NetIdentifier>>;
    // Query labels on team.
    async fn query_labels(team: TeamId) -> Result<Vec<Label>>;
    /// Query whether a label exists.
    async fn query_label_exists(team: TeamId, label: LabelId) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use aranya_crypto::Rng;
    use serde::de::DeserializeOwned;

    use super::*;

    fn secret(secret: &[u8]) -> Secret {
        Secret(Box::from(secret))
    }

    pub(super) trait PskMap:
        fmt::Debug + PartialEq + Serialize + DeserializeOwned + Sized
    {
        type Psk;
        fn new() -> Self;
        /// Returns the number of PSKs in the map.
        fn len(&self) -> usize;
        /// Adds `psk` to the map.
        ///
        /// # Panics
        ///
        /// Panics if `psk` already exists.
        fn insert(&mut self, psk: Self::Psk);
    }

    impl PartialEq for AqcBidiPsk {
        fn eq(&self, other: &Self) -> bool {
            bool::from(self.ct_eq(other))
        }
    }
    impl PartialEq for AqcUniPsk {
        fn eq(&self, other: &Self) -> bool {
            bool::from(self.ct_eq(other))
        }
    }
    impl PartialEq for AqcPsk {
        fn eq(&self, other: &Self) -> bool {
            bool::from(self.ct_eq(other))
        }
    }

    #[track_caller]
    fn psk_map_test<M, F>(name: &'static str, mut f: F)
    where
        M: PskMap,
        F: FnMut(Secret, Id, CipherSuiteId) -> M::Psk,
    {
        let mut psks = M::new();
        for (i, &suite) in CipherSuiteId::all().iter().enumerate() {
            let id = Id::random(&mut Rng);
            let secret = secret(&i.to_le_bytes());
            psks.insert(f(secret, id, suite));
        }
        assert_eq!(psks.len(), CipherSuiteId::all().len(), "{name}");

        let bytes = postcard::to_allocvec(&psks).unwrap();
        let got = postcard::from_bytes::<M>(&bytes).unwrap();
        assert_eq!(got, psks, "{name}")
    }

    /// Test that we can correctly serialize and deserialize
    /// [`AqcBidiPsk`].
    #[test]
    fn test_aqc_bidi_psks_serde() {
        psk_map_test::<AqcBidiPsks, _>("AqcBidiPsk", |secret, id, suite| AqcBidiPsk {
            identity: BidiPskId::from((id.into(), suite)),
            secret,
        });
    }

    /// Test that we can correctly serialize and deserialize
    /// [`AqcUniPsk`].
    #[test]
    fn test_aqc_uni_psks_serde() {
        psk_map_test::<AqcUniPsks, _>("AqcUniPsk (send)", |secret, id, suite| AqcUniPsk {
            identity: UniPskId::from((id.into(), suite)),
            secret: Directed::Send(secret),
        });
        psk_map_test::<AqcUniPsks, _>("AqcUniPsk (recv)", |secret, id, suite| AqcUniPsk {
            identity: UniPskId::from((id.into(), suite)),
            secret: Directed::Recv(secret),
        });
    }
}
