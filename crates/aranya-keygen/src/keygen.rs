use core::fmt;

use anyhow::{Context, Result};
use aranya_crypto::{
    CipherSuite, DeviceId, EncryptionKey, EncryptionKeyId, EncryptionPublicKey, Engine,
    IdentityKey, IdentityVerifyingKey, KeyStore, KeyStoreExt as _, SigningKey, SigningKeyId,
    VerifyingKey,
};
use serde::{Deserialize, Serialize};

/// A bundle of cryptographic keys for secure communication in Aranya.
///
/// A PublicKeyBundle contains identifiers for three types of keys:
/// - Device identity key: Used to identify a device in an Aranya team. A device's ID
///   is derived from the public portion of the device identity key. The device key is
///   used for digital signatures allowing others to verify signatures created with this key.
/// - Encryption key: Used for secure data encryption and decryption. This key is used
///   for the encapsulation and decapsulation of KEM shared secrets.
/// - Signing key: Used for creating and verifying cryptographic signatures. Whenever
///   this device publishes a command, it is signed using the secret portion of this key.
///   Other devices can use the public portion of this key to verify those signatures.
///
/// The actual key material is stored in the provided `KeyStore`, and this
/// structure only contains references to those keys.
///
/// # Example
///
/// ```
/// # use anyhow::Result;
/// # use aranya_crypto::{Engine, KeyStore};
/// # use aranya_keygen::PublicKeyBundle;
/// #
/// # fn example<CE, KS>(engine: &CE, store: &mut KS) -> Result<()>
/// # where
/// #     CE: Engine,
/// #     KS: KeyStore,
/// # {
/// // Generate a new key bundle and store the keys in the keystore
/// let key_bundle = PublicKeyBundle::generate(engine, store)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PublicKeyBundle {
    /// Device identifier derived from the identity key.
    ///
    /// This ID uniquely identifies the device in the Aranya team.
    ///
    /// See [`IdentityKey`].
    pub device_id: DeviceId,

    /// Identifier for the encryption key.
    ///
    /// The encryption key in the keybundle is used for the secure
    /// sharing of KEM shared secrets.
    ///
    /// See [`EncryptionKey`].
    pub enc_id: EncryptionKeyId,

    /// Identifier for the signing key.
    ///
    /// The signing key is used for creating cryptographic signatures that can be
    /// verified using the corresponding public key. This key is used to sign
    /// commands published by this device.
    ///
    /// See [`SigningKey`].
    pub sign_id: SigningKeyId,
}

/// Collection of public keys derived from a [`PublicKeyBundle`].
///
/// This structure contains the public portions of the keys referenced in a PublicKeyBundle.
/// These public keys can be shared with other devices for secure communication.
///
/// - `ident_pk`: Public identity key for device identification
/// - `enc_pk`: Public encryption key for encrypting messages to this device
/// - `sign_pk`: Public verification key for verifying signatures from this device
///
/// # Type Parameters
///
/// * `CS` - The cipher suite implementation to use for cryptographic operations
#[derive(Clone)]
#[non_exhaustive]
pub struct PublicKeys<CS: CipherSuite> {
    /// Public identity key for device identification.
    pub ident_pk: IdentityVerifyingKey<CS>,

    /// Public encryption key for securely exchanging KEM shared secrets.
    pub enc_pk: EncryptionPublicKey<CS>,

    /// Public verification key for verifying command signatures from this device.
    pub sign_pk: VerifyingKey<CS>,
}

impl PublicKeyBundle {
    /// Generates a new key bundle with fresh cryptographic keys.
    ///
    /// This method creates new identity, encryption, and signing keys using the provided
    /// engine, wraps them, and stores them in the provided key store. It returns a PublicKeyBundle
    /// that contains references to these stored keys.
    ///
    /// # Type Parameters
    ///
    /// * `CE` - The cryptographic engine implementation
    /// * `KS` - The key store implementation
    ///
    /// # Arguments
    ///
    /// * `eng` - The cryptographic engine to use for key generation
    /// * `store` - The key store where the generated keys will be stored
    ///
    /// # Returns
    ///
    /// A Result containing the new PublicKeyBundle if successful, or an error if key generation,
    /// wrapping, or storage fails.
    ///
    /// # Example
    ///
    /// ```
    /// # use anyhow::Result;
    /// # use aranya_crypto::{Engine, KeyStore};
    /// # use aranya_keygen::PublicKeyBundle;
    /// #
    /// # fn example<CE, KS>(engine: &CE, store: &mut KS) -> Result<()>
    /// # where
    /// #     CE: Engine,
    /// #     KS: KeyStore,
    /// # {
    /// let key_bundle = PublicKeyBundle::generate(engine, store)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate<CE, KS>(eng: &CE, store: &mut KS) -> Result<Self>
    where
        CE: Engine,
        KS: KeyStore,
    {
        macro_rules! gen {
            ($key:ident) => {{
                let sk = $key::<CE::CS>::new(eng);
                store.insert_key(eng, sk).context(concat!(
                    "unable to insert `",
                    stringify!($key),
                    "`"
                ))?
            }};
        }
        Ok(Self {
            device_id: gen!(IdentityKey),
            enc_id: gen!(EncryptionKey),
            sign_id: gen!(SigningKey),
        })
    }

    /// Loads the public keys associated with this key bundle.
    ///
    /// This method loads the keys referenced by this PublicKeyBundle from the provided key store,
    /// extracts their public portions, and returns them in a PublicKeys structure.
    ///
    /// # Type Parameters
    ///
    /// * `CE` - The cryptographic engine implementation
    /// * `KS` - The key store implementation
    ///
    /// # Arguments
    ///
    /// * `eng` - The cryptographic engine to use for key operations
    /// * `store` - The key store from which to load the keys
    ///
    /// # Returns
    ///
    /// A Result containing the PublicKeys if successful, or an error if key loading or
    /// public key extraction fails.
    ///
    /// # Example
    ///
    /// ```
    /// # use anyhow::Result;
    /// # use aranya_crypto::{Engine, KeyStore};
    /// # use aranya_keygen::PublicKeyBundle;
    /// #
    /// # fn example<CE, KS>(engine: &CE, store: &mut KS) -> Result<()>
    /// # where
    /// #     CE: Engine,
    /// #     KS: KeyStore,
    /// # {
    /// let key_bundle = PublicKeyBundle::generate(engine, store)?;
    /// let public_keys = key_bundle.public_keys(engine, store)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn public_keys<CE, KS>(&self, eng: &CE, store: &KS) -> Result<PublicKeys<CE::CS>>
    where
        CE: Engine,
        KS: KeyStore,
    {
        Ok(PublicKeys {
            ident_pk: store
                .get_key::<_, IdentityKey<CE::CS>>(eng, self.device_id)
                .context("unable to load `IdentityKey`")?
                .context("unable to find `IdentityKey`")?
                .public()?,
            enc_pk: store
                .get_key::<_, EncryptionKey<CE::CS>>(eng, self.enc_id)
                .context("unable to load `EncryptionKey`")?
                .context("unable to find `EncryptionKey`")?
                .public()?,
            sign_pk: store
                .get_key::<_, SigningKey<CE::CS>>(eng, self.sign_id)
                .context("unable to load `SigningKey`")?
                .context("unable to find `SigningKey`")?
                .public()?,
        })
    }
}

impl<CS: CipherSuite> fmt::Debug for PublicKeys<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeys")
            .field("ident_pk", &self.ident_pk)
            .field("enc_pk", &self.ident_pk)
            .field("sign_pk", &self.sign_pk)
            .finish_non_exhaustive()
    }
}
