#![cfg(feature = "aqc")]
#![cfg_attr(docsrs, doc(cfg(feature = "aqc")))]

use core::hash::{Hash, Hasher};
use std::collections::hash_map::{self, HashMap};

use anyhow::bail;
use aranya_crypto::{
    aqc::{BidiPskId, CipherSuiteId, UniPskId},
    custom_id,
    subtle::{Choice, ConstantTimeEq},
    zeroize::ZeroizeOnDrop,
    Id,
};
pub use aranya_policy_text::{text, Text};
pub use semver::Version;
use serde::{Deserialize, Serialize};

use super::Secret;

custom_id! {
    /// An AQC bidi channel ID.
    pub struct AqcBidiChannelId;
}

custom_id! {
    /// An AQC uni channel ID.
    pub struct AqcUniChannelId;
}

/// A serialized command for AQC.
pub type AqcCtrl = Vec<Box<[u8]>>;

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

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use aranya_crypto::{id::IdExt as _, Rng};
    use serde::de::DeserializeOwned;

    use super::*;

    fn secret(secret: &[u8]) -> Secret {
        Secret(Box::from(secret))
    }

    pub(super) trait PskMap:
        Debug + PartialEq + Serialize + DeserializeOwned + Sized
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
