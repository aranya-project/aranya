use std::{path::PathBuf, sync::Arc};

use anyhow::{Context as _, Result};
use aranya_crypto::{Id, KeyStoreExt};
use aranya_daemon_api::{QuicSyncSeed, QuicSyncSeedId, TeamId};
use aranya_util::create_dir_all;
use s2n_quic::provider::tls::rustls::rustls::crypto::{hash::HashAlgorithm, PresharedKey};
use tokio::{
    fs::{read, read_dir, OpenOptions},
    io::AsyncWriteExt,
};

use crate::{CE, CS, KS};

#[derive(Debug)]
pub(crate) struct SeedDir(PathBuf);

impl SeedDir {
    pub(crate) async fn new(p: PathBuf) -> Result<Self> {
        create_dir_all(&p).await?;
        Ok(Self(p))
    }

    pub(crate) async fn append(&self, team_id: &TeamId, seed_id: &QuicSyncSeedId) -> Result<()> {
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

    pub(crate) async fn get(&self, team_id: &TeamId) -> Result<QuicSyncSeedId> {
        let path = self.0.join(team_id.to_string());
        Self::read_id(path).await
    }

    pub(crate) async fn list(&self) -> Result<Vec<(TeamId, QuicSyncSeedId)>> {
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

    async fn read_id(path: PathBuf) -> Result<QuicSyncSeedId> {
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
    id: &QuicSyncSeedId,
) -> Result<Option<QuicSyncSeed<CS>>> {
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
        let psk = seed.gen_psk()?;

        let identity = psk.identity();
        let secret = psk.raw_secret();
        let psk = PresharedKey::external(identity, secret)
            .context("unable to create PSK")?
            .with_hash_alg(HashAlgorithm::SHA384)
            .context("invalid hash algorithm")?;

        out.push((team_id, Arc::new(psk)));
    }

    Ok(out)
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
