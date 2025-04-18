use core::{borrow::Borrow, fmt, marker::PhantomData};

use anyhow::{Context, Result};
use aranya_crypto::{
    custom_id,
    engine::{AlgId, RawSecret, Secret, UnwrappedKey, UnwrappedSecret, WrongKeyType},
    id::{Id, IdError, Identified},
    import::ImportError,
    kem::{DecapKey as _, Kem},
    keys::{PublicKey, SecretKey},
    keystore::KeyStore,
    signer::PkError,
    CipherSuite, Engine,
};
use postcard::experimental::max_size::MaxSize;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

custom_id! {
    /// Uniquely identifies an [`ApiKey`].
    pub struct ApiKeyId;
}

/// The daemon's secret key used to encrypt data sent over the
/// API.
pub(crate) struct ApiKey<CS: CipherSuite>(<<CS as CipherSuite>::Kem as Kem>::DecapKey);

impl<CS: CipherSuite> ApiKey<CS> {
    pub(crate) fn id(&self) -> Result<ApiKeyId, IdError> {
        self.public()?.id()
    }

    pub(crate) fn public(&self) -> Result<PublicApiKey<CS>, PkError> {
        Ok(PublicApiKey(self.0.public()?))
    }

    pub(crate) fn into_inner(self) -> <<CS as CipherSuite>::Kem as Kem>::DecapKey {
        self.0
    }

    pub(crate) fn generate<E, S>(eng: &mut E, store: &mut S) -> Result<Self>
    where
        E: Engine<CS = CS>,
        S: KeyStore,
    {
        let sk = Self(<<<CS as CipherSuite>::Kem as Kem>::DecapKey as SecretKey>::new(eng));
        let id = sk.id()?;
        let wrapped = eng
            .wrap(sk.clone())
            .context(concat!("unable to wrap `ApiKey`"))?;
        store
            .try_insert(id.into(), wrapped)
            .context(concat!("unable to insert wrapped `ApiKey`"))?;
        Ok(sk)
    }
}

impl<CS: CipherSuite> Clone for ApiKey<CS> {
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

// TODO(eric): use `aranya_crypto::unwrapped` instead once
// `__unwrapped_inner` is exported. Oops.
impl<CS: CipherSuite> UnwrappedKey<CS> for ApiKey<CS> {
    const ID: AlgId = AlgId::Decap(<CS::Kem as Kem>::ID);

    #[inline]
    fn into_secret(self) -> Secret<CS> {
        Secret::new(RawSecret::Decap(self.0))
    }

    #[inline]
    fn try_from_secret(key: UnwrappedSecret<CS>) -> Result<Self, WrongKeyType> {
        match key.into_raw() {
            RawSecret::Decap(key) => Ok(Self(key)),
            got => Err(WrongKeyType {
                got: got.name(),
                expected: ::core::stringify!($name),
            }),
        }
    }
}

/// The public half of [`ApiKey`].
pub(crate) struct PublicApiKey<CS: CipherSuite>(<<CS as CipherSuite>::Kem as Kem>::EncapKey);

impl<CS: CipherSuite> PublicApiKey<CS> {
    pub(crate) fn id(&self) -> Result<ApiKeyId, IdError> {
        let pk = &self.0.export();
        let id = Id::new::<CS>(pk.borrow(), b"ApiKey");
        Ok(ApiKeyId(id))
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
        ExportedData::from_key::<CS>(&self.0, ExportedDataType::PublicApiKey).serialize(serializer)
    }
}

impl<'de, CS: CipherSuite> Deserialize<'de> for PublicApiKey<CS> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = ExportedData::<SerdeOwnedKey<_>>::deserialize(deserializer)?;
        if !data.valid_context::<CS>(ExportedDataType::PublicApiKey) {
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
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, MaxSize)]
pub(crate) enum ExportedDataType {
    PublicApiKey,
}

/// Non-secret exported from an `Engine`.
#[derive(Serialize, Deserialize, MaxSize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportedData<T> {
    /// Uniquely idenitifes the type of data.
    name: ExportedDataType,
    /// The exported data.
    pub(crate) data: T,
}

impl<T> ExportedData<T> {
    pub(crate) fn valid_context<CS: CipherSuite>(&self, name: ExportedDataType) -> bool {
        self.name == name
    }
}

impl<'a, K: PublicKey> ExportedData<SerdeBorrowedKey<'a, K>> {
    pub(crate) fn from_key<CS: CipherSuite>(pk: &'a K, name: ExportedDataType) -> Self {
        Self {
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
pub(crate) struct SerdeBorrowedKey<'a, K>(&'a K);

impl<K: PublicKey> Serialize for SerdeBorrowedKey<'_, K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.export().borrow())
    }
}
