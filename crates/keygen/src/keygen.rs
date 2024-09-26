use anyhow::{Context, Result};
use crypto::{
    CipherSuite, EncryptionKey, EncryptionKeyId, EncryptionPublicKey, Engine, IdentityKey,
    IdentityVerifyingKey, KeyStore, KeyStoreExt, SigningKey, SigningKeyId, UserId, VerifyingKey,
};
use serde::{Deserialize, Serialize};

/// A key bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBundle {
    /// See [`IdentityKey`].
    pub user_id: UserId,
    /// See [`EncryptionKey`].
    pub enc_id: EncryptionKeyId,
    /// See [`SigningKey`].
    pub sign_id: SigningKeyId,
}

/// Public keys from key bundle.
#[derive(Debug)]
pub struct PublicKeys<CS: CipherSuite> {
    /// Public identity key.
    pub ident_pk: IdentityVerifyingKey<CS>,
    /// Public encryption key.
    pub enc_pk: EncryptionPublicKey<CS>,
    /// Public signing key.
    pub sign_pk: VerifyingKey<CS>,
}

impl KeyBundle {
    /// Generates a key bundle.
    ///
    /// The wrapped keys are stored inside of `store`.
    pub fn generate<E, S>(eng: &mut E, store: &mut S) -> Result<Self>
    where
        E: Engine,
        S: KeyStore,
    {
        macro_rules! gen {
            ($key:ident) => {{
                let sk = $key::<E::CS>::new(eng);
                let id = sk.id()?;
                let wrapped =
                    eng.wrap(sk)
                        .context(concat!("unable to wrap `", stringify!($key), "`"))?;
                store.try_insert(id.into(), wrapped).context(concat!(
                    "unable to insert wrapped `",
                    stringify!($key),
                    "`"
                ))?;
                id
            }};
        }
        Ok(Self {
            user_id: gen!(IdentityKey),
            enc_id: gen!(EncryptionKey),
            sign_id: gen!(SigningKey),
        })
    }

    /// Loads the public keys from `store`.
    pub fn public_keys<E, S>(&self, eng: &mut E, store: &S) -> Result<PublicKeys<E::CS>>
    where
        E: Engine,
        S: KeyStore,
    {
        Ok(PublicKeys {
            ident_pk: store
                .get_key::<_, IdentityKey<E::CS>>(eng, &self.user_id.into())
                .context("unable to load `IdentityKey`")?
                .context("unable to find `IdentityKey`")?
                .public()?,
            enc_pk: store
                .get_key::<_, EncryptionKey<E::CS>>(eng, &self.enc_id.into())
                .context("unable to load `EncryptionKey`")?
                .context("unable to find `EncryptionKey`")?
                .public()?,
            sign_pk: store
                .get_key::<_, SigningKey<E::CS>>(eng, &self.sign_id.into())
                .context("unable to load `SigningKey`")?
                .context("unable to find `SigningKey`")?
                .public()?,
        })
    }
}
