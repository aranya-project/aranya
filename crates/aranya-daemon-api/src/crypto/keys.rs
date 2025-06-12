use core::{borrow::Borrow, fmt, marker::PhantomData};

use anyhow::Result;
use aranya_crypto::{
    custom_id,
    dangerous::spideroak_crypto::{
        import::ImportError,
        kem::{DecapKey as _, Kem},
        keys::PublicKey,
        signer::PkError,
    },
    id::{Id, IdError, Identified},
    unwrapped, CipherSuite, Engine, Oids, Random,
};
use ciborium as cbor;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

custom_id! {
    /// Uniquely identifies an [`ApiKey`].
    pub struct ApiKeyId;
}

/// The daemon's secret key used to encrypt data sent over the
/// API.
pub struct ApiKey<CS: CipherSuite>(<<CS as CipherSuite>::Kem as Kem>::DecapKey);

impl<CS: CipherSuite> ApiKey<CS> {
    pub(crate) fn new<E>(eng: &mut E) -> Self
    where
        E: Engine<CS = CS>,
    {
        Self(Random::random(eng))
    }

    /// Returns the key's unique ID.
    #[inline]
    pub fn id(&self) -> Result<ApiKeyId, IdError> {
        self.public()?.id()
    }

    /// Returns the public half of the key.
    pub fn public(&self) -> Result<PublicApiKey<CS>, PkError> {
        Ok(PublicApiKey(self.0.public()?))
    }

    pub(crate) fn as_inner(&self) -> &<<CS as CipherSuite>::Kem as Kem>::DecapKey {
        &self.0
    }

    /// Generates a random API key.
    pub fn generate<E>(eng: &mut E) -> Self
    where
        E: Engine<CS = CS>,
    {
        Self::new(eng)
    }
}

impl<CS: CipherSuite> Clone for ApiKey<CS> {
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<CS: CipherSuite> fmt::Display for ApiKey<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id().map_err(|_| fmt::Error)?)
    }
}

impl<CS: CipherSuite> fmt::Debug for ApiKey<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ApiKey")
            .field(&self.id().map_err(|_| fmt::Error)?)
            .finish()
    }
}

impl<CS: CipherSuite> Identified for ApiKey<CS> {
    type Id = ApiKeyId;

    #[inline]
    fn id(&self) -> Result<Self::Id, IdError> {
        self.id()
    }
}

unwrapped! {
    name: ApiKey;
    type: Decap;
    into: |key: Self| { key.0 };
    from: |key| { Self(key) };
}

/// The public half of [`ApiKey`].
pub struct PublicApiKey<CS: CipherSuite>(<<CS as CipherSuite>::Kem as Kem>::EncapKey);

impl<CS: CipherSuite> PublicApiKey<CS> {
    /// Returns the key's unique ID.
    #[inline]
    pub fn id(&self) -> Result<ApiKeyId, IdError> {
        let pk = &self.0.export();
        let id = Id::new::<CS>(pk.borrow(), b"ApiKey");
        Ok(ApiKeyId(id))
    }

    pub(crate) fn as_inner(&self) -> &<<CS as CipherSuite>::Kem as Kem>::EncapKey {
        &self.0
    }

    /// Encodes the public key as bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        cbor::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Decodes the public key from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        Ok(cbor::from_reader(data)?)
    }
}

impl<CS: CipherSuite> Clone for PublicApiKey<CS> {
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<CS: CipherSuite> AsRef<PublicApiKey<CS>> for PublicApiKey<CS> {
    #[inline]
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<CS: CipherSuite> Eq for PublicApiKey<CS> {}
impl<CS: CipherSuite> PartialEq for PublicApiKey<CS> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        match (self.id(), other.id()) {
            (Ok(lhs), Ok(rhs)) => lhs == rhs,
            _ => false,
        }
    }
}

impl<CS: CipherSuite> fmt::Display for PublicApiKey<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id().map_err(|_| fmt::Error)?)
    }
}

impl<CS: CipherSuite> fmt::Debug for PublicApiKey<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            concat!(stringify!(PublicApiKey), " {}"),
            self.id().map_err(|_| fmt::Error)?
        )
    }
}

impl<CS: CipherSuite> Serialize for PublicApiKey<CS> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ExportedData::<CS, _>::from_key(&self.0, ExportedDataType::PublicApiKey)
            .serialize(serializer)
    }
}

impl<'de, CS: CipherSuite> Deserialize<'de> for PublicApiKey<CS> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = ExportedData::<CS, SerdeOwnedKey<_>>::deserialize(deserializer)?;
        if !data.is_type(ExportedDataType::PublicApiKey) {
            Err(de::Error::custom(ImportError::InvalidContext))
        } else {
            Ok(Self(data.data.0))
        }
    }
}

impl<CS: CipherSuite> Identified for PublicApiKey<CS> {
    type Id = ApiKeyId;

    #[inline]
    fn id(&self) -> Result<Self::Id, IdError> {
        self.id()
    }
}

// Allow repeated suffixes since different types will be added in
// the future.
#[allow(clippy::enum_variant_names)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ExportedDataType {
    PublicApiKey,
}

/// Non-secret exported from an `Engine`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportedData<CS, T>
where
    CS: CipherSuite,
{
    /// Uniquely idenitifies the chosen algorithms.
    #[serde(bound = "CS: CipherSuite")]
    oids: Oids<CS>,
    /// Uniquely idenitifes the type of data.
    name: ExportedDataType,
    /// The exported data.
    pub(crate) data: T,
}

impl<CS, T> ExportedData<CS, T>
where
    CS: CipherSuite,
{
    pub(crate) fn is_type(&self, name: ExportedDataType) -> bool {
        self.name == name
    }
}

impl<'a, CS, K: PublicKey> ExportedData<CS, SerdeBorrowedKey<'a, K>>
where
    CS: CipherSuite,
{
    pub(crate) fn from_key(pk: &'a K, name: ExportedDataType) -> Self {
        Self {
            oids: CS::OIDS,
            name,
            data: SerdeBorrowedKey(pk),
        }
    }
}

/// An owned [`PublicKey`] for deserializing.
pub(crate) struct SerdeOwnedKey<K>(pub(crate) K);

impl<'de, K: PublicKey> Deserialize<'de> for SerdeOwnedKey<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PkVisitor<K>(PhantomData<K>);

        impl<'de, K: PublicKey> de::Visitor<'de> for PkVisitor<K> {
            type Value = K;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a public key")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                K::import(v).map_err(de::Error::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                K::import(v).map_err(de::Error::custom)
            }
        }
        let pk = deserializer.deserialize_bytes(PkVisitor::<K>(PhantomData))?;
        Ok(SerdeOwnedKey(pk))
    }
}

/// A borrowed [`PublicKey`] for serializing.
struct SerdeBorrowedKey<'a, K>(&'a K);

impl<K: PublicKey> Serialize for SerdeBorrowedKey<'_, K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.export().borrow())
    }
}
