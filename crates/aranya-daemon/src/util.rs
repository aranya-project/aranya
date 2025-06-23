use std::{path::PathBuf, sync::Arc};

use anyhow::{bail, Context as _, Result};
use aranya_crypto::{
    default::WrappedKey,
    tls::{CipherSuiteId, Psk, PskSeed, PskSeedId},
    Engine, Id, Identified as _, KeyStore, KeyStoreExt, PolicyId,
};
use aranya_daemon_api::TeamId;
use aranya_util::create_dir_all;
use s2n_quic::provider::tls::rustls::rustls::crypto::{hash::HashAlgorithm, PresharedKey};
use tokio::{
    fs::{read, read_dir, OpenOptions},
    io::AsyncWriteExt,
};

use crate::{keystore::LocalStore, sync::task::quic::QUIC_SYNC_PSK_CONTEXT, CE, CS, KS};

#[derive(Debug)]
pub(crate) struct SeedDir(PathBuf);

impl SeedDir {
    pub(crate) async fn new(p: PathBuf) -> Result<Self> {
        create_dir_all(&p).await?;
        Ok(Self(p))
    }

    pub(crate) async fn append(&self, team_id: &TeamId, seed_id: &PskSeedId) -> Result<()> {
        let file_name = self.0.join(team_id.to_string());

        // fail if a file with the same name already exists
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(file_name)
            .await?;

        file.write_all(seed_id.as_bytes()).await?;
        file.flush().await?;

        Ok(())
    }

    pub(crate) async fn list(&self) -> Result<Vec<(TeamId, PskSeedId)>> {
        let mut entries = read_dir(&self.0).await?;
        let mut out = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name().into_string().map_err(|s| {
                anyhow::anyhow!("could not convert OsString: `{:?}` into String", s)
            })?;
            let team_id = TeamId::decode(file_name)?;

            let seed_id = Self::read_id(entry.path()).await?;

            out.push((team_id, seed_id));
        }

        Ok(out)
    }

    async fn read_id(path: PathBuf) -> Result<PskSeedId> {
        const ID_SIZE: usize = size_of::<Id>();
        let bytes = read(path).await?;
        let arr: [u8; ID_SIZE] = bytes.try_into().map_err(|input| {
            anyhow::anyhow!(
                "could not convert {:?} to an array of {ID_SIZE} bytes",
                input
            )
        })?;
        Ok(arr.into())
    }
}

#[inline]
pub(crate) fn load_seed(
    eng: &mut CE,
    store: &mut KS,
    id: &PskSeedId,
) -> Result<Option<PskSeed<CS>>> {
    store.get_key(eng, id.into_id()).map_err(Into::into)
}

pub(crate) async fn load_team_psk_pairs(
    eng: &mut CE,
    store: &mut KS,
    dir: &SeedDir,
) -> Result<Vec<(TeamId, Arc<PresharedKey>)>> {
    let pairs = dir.list().await?;
    let mut out = Vec::new();

    for (team_id, seed_id) in pairs {
        let Some(seed) = load_seed(eng, store, &seed_id)? else {
            continue;
        };

        // Groups are teams for now.
        let group_id = team_id.into_id().into();
        // TODO: Use real value for policy ID
        let policy_id = PolicyId::default();
        let psk_iter = seed
            .generate_psks(
                QUIC_SYNC_PSK_CONTEXT,
                group_id,
                policy_id,
                CipherSuiteId::all().iter().copied(),
            )
            .flatten();
        for psk in psk_iter {
            let psk = psk_to_rustls(psk)?;
            out.push((team_id, Arc::new(psk)));
        }
    }

    Ok(out)
}

fn psk_to_rustls(psk: Psk<CS>) -> Result<PresharedKey> {
    let identity = psk.identity().as_bytes();
    let secret = psk.raw_secret_bytes();
    let alg = match psk.identity().cipher_suite() {
        CipherSuiteId::TlsAes128GcmSha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes256GcmSha384 => HashAlgorithm::SHA384,
        CipherSuiteId::TlsChaCha20Poly1305Sha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes128CcmSha256 => HashAlgorithm::SHA256,
        CipherSuiteId::TlsAes128Ccm8Sha256 => HashAlgorithm::SHA256,
        cs => bail!("unknown ciphersuite {cs}"),
    };
    let psk = PresharedKey::external(identity, secret)
        .context("unable to create PSK")?
        .with_hash_alg(alg)
        .context("Invalid hash algorithm")?;
    Ok(psk)
}

/// Inserts a seed into the daemon's local keystore
pub(crate) fn insert_seed(
    eng: &mut CE,
    store: &mut LocalStore<KS>,
    seed: PskSeed<CS>,
) -> Result<()> {
    store.try_insert(seed.id()?.into_id(), eng.wrap(seed)?)?;
    Ok(())
}

/// Removes a seed from the daemon's local keystore
pub(crate) fn remove_seed(store: &mut LocalStore<KS>, seed: PskSeed<CS>) -> Result<()> {
    store.remove::<WrappedKey<CS>>(seed.id()?.into_id())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use aranya_crypto::Rng;
    use tempfile::tempdir;
    use test_log::test;

    use super::*;

    #[test(tokio::test(flavor = "multi_thread"))]
    async fn test_append_and_list() -> Result<()> {
        let tmp_dir = tempdir()?;
        let path = tmp_dir.path().join("seeds");

        let seed_dir = SeedDir::new(path)
            .await
            .context("could not create seed dir")?;

        let mut expected = Vec::new();
        let mut seen = HashSet::new();

        for _ in 0..100 {
            let team_id = Id::random(&mut Rng).into();
            let seed_id = Id::random(&mut Rng).into();

            // may see duplicates by random chance
            if !seen.insert(team_id) {
                continue;
            }

            seed_dir
                .append(&team_id, &seed_id)
                .await
                .context("could not append")?;

            expected.push((team_id, seed_id));
        }

        let mut out = seed_dir.list().await?;
        out.sort_unstable();

        expected.sort_unstable();

        assert_eq!(out, expected);

        Ok(())
    }
}
