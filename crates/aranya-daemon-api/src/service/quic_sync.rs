#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::hash::Hash;
use std::marker::PhantomData;

use anyhow::Context as _;
use aranya_crypto::{
    custom_id,
    dangerous::spideroak_crypto::kdf::Kdf,
    id::IdError,
    unwrapped,
    zeroize::{Zeroize, ZeroizeOnDrop},
    CipherSuite, Id, Identified,
};
use serde::{Deserialize, Serialize};

use super::{Result, Secret};

custom_id! {
    /// A QUIC sync seed ID.
    pub struct QuicSyncSeedId;
}

custom_id! {
    /// A QUIC sync PSK ID.
    pub struct QuicSyncPskId;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuicSyncConfig {
    seed: GenSeedMode,
}

impl QuicSyncConfig {
    pub fn builder() -> QuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }

    pub fn seed(&self) -> &GenSeedMode {
        &self.seed
    }
}

#[derive(Default)]
pub struct QuicSyncConfigBuilder {
    seed: Option<GenSeedMode>,
}

impl QuicSyncConfigBuilder {
    /// Sets the seed type.
    pub fn seed(mut self, seed: GenSeedMode) -> Self {
        self.seed = Some(seed);
        self
    }

    pub fn build(self) -> anyhow::Result<QuicSyncConfig> {
        Ok(QuicSyncConfig {
            seed: self.seed.context("Missing `seed` field")?,
        })
    }
}

impl<CS: CipherSuite> Identified for QuicSyncSeed<CS> {
    type Id = QuicSyncSeedId;

    fn id(&self) -> std::result::Result<Self::Id, IdError> {
        Ok(self.id())
    }
}

/// A QUIC syncer PSK.
#[derive(Debug, Clone)]
pub struct QuicSyncPSK<CS> {
    id: QuicSyncPskId,
    secret: Secret,
    _cs: PhantomData<CS>,
}

impl<CS> QuicSyncPSK<CS> {
    fn new(identity: [u8; 32], secret: [u8; 64]) -> Self {
        Self {
            id: identity.into(),
            secret: Secret::from(secret),
            _cs: PhantomData,
        }
    }

    pub fn identity(&self) -> &[u8] {
        self.id.as_bytes()
    }

    pub fn raw_secret(&self) -> &[u8] {
        self.secret.raw_secret_bytes()
    }
}

/// A secret seed that a KDF can derive a PSK from..
#[derive(Debug)]
pub struct QuicSyncSeed<CS> {
    seed: [u8; 64],
    _cs: PhantomData<CS>,
}

impl<CS: CipherSuite> QuicSyncSeed<CS> {
    pub fn key_id(&self) -> Id {
        self.id().into()
    }

    #[inline]
    pub fn id(&self) -> QuicSyncSeedId {
        Id::new::<CS>(&self.seed, b"QuicSyncKeyId-v1").into()
    }

    pub fn from_ikm(ikm: [u8; 64]) -> Self {
        let prk = <CS::Kdf as Kdf>::extract(&ikm, &[]);
        let mut seed = [0; 64];
        <CS::Kdf as Kdf>::expand(&mut seed, &prk, b"quic sync seed").expect("can create seed");

        Self::from_seed(seed)
    }

    const fn from_seed(seed: [u8; 64]) -> Self {
        Self {
            seed,
            _cs: PhantomData,
        }
    }

    pub fn gen_psk(&self) -> Result<QuicSyncPSK<CS>> {
        let prk = <CS::Kdf as Kdf>::extract(&self.seed, &[]);

        let identity = {
            let mut buf = [0; 32];
            <CS::Kdf as Kdf>::expand(&mut buf, &prk, b"quic sync psk identity")
                .context("could not create identity")?;
            buf
        };

        let key = {
            let mut buf = [0; 64];
            <CS::Kdf as Kdf>::expand(&mut buf, &prk, b"quic sync psk secret")
                .context("could not create identity")?;
            buf
        };

        Ok(QuicSyncPSK::new(identity, key))
    }
}

impl<CS> ZeroizeOnDrop for QuicSyncSeed<CS> {}
impl<CS> Drop for QuicSyncSeed<CS> {
    fn drop(&mut self) {
        self.seed.zeroize()
    }
}

impl<CS> Clone for QuicSyncSeed<CS> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            _cs: PhantomData,
        }
    }
}

unwrapped! {
    name: QuicSyncSeed;
    type: Seed;
    into: |key: Self| { key.seed };
    from: |seed: [u8;64] | { Self::from_seed(seed) };

}

// TODO: Create analogous type in aranya-client
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GenSeedMode {
    /// The default option. Used in the create_team API
    Generate,
    /// Used in the create_team and add_team APIs
    IKM(Box<[u8]>),
    /// Used in the add_team API
    Wrapped { recv_pk: Box<[u8]> },
}

impl Default for GenSeedMode {
    fn default() -> Self {
        Self::Generate
    }
}

#[cfg(test)]
mod test {
    use aranya_crypto::{Random, Rng};

    use super::*;
    use crate::CS;

    #[test]
    fn test_from_ikm() {
        let ikm = <[u8; 64] as Random>::random(&mut Rng);
        let expected = QuicSyncSeed::<CS>::from_ikm(ikm);

        for _ in 0..100 {
            let got = QuicSyncSeed::<CS>::from_ikm(ikm);
            assert_eq!(got.seed, expected.seed);
        }
    }
}
