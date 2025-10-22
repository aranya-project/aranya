use core::{error, fmt};
use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use aranya_crypto::{keystore::fs_keystore, tls::PskSeedId};
use aranya_daemon_api::TeamId;
use aranya_util::create_dir_all;
use s2n_quic::provider::tls::rustls::rustls::crypto::PresharedKey;
use tokio::{
    fs::{read, read_dir, remove_file, File},
    io::AsyncWriteExt,
};

use crate::{
    daemon::{CE, KS},
    keystore::LocalStore,
    sync::task::quic::{self as qs},
};

#[derive(Debug)]
pub(crate) struct SeedDir(PathBuf);

impl SeedDir {
    pub(crate) async fn new(p: PathBuf) -> Result<Self> {
        create_dir_all(&p).await?;
        Ok(Self(p))
    }

    pub(crate) async fn get(&self, team_id: &TeamId) -> Result<PskSeedId> {
        Self::read_id(self.0.join(team_id.to_string())).await
    }

    pub(crate) async fn append(&self, team_id: &TeamId, seed_id: &PskSeedId) -> Result<()> {
        let file_name = self.0.join(team_id.to_string());

        // fail if a file with the same name already exists
        let mut file = File::create_new(file_name).await?;

        file.write_all(seed_id.as_bytes()).await?;
        file.sync_data().await?;

        Ok(())
    }

    pub(crate) async fn remove(&self, team_id: &TeamId) -> Result<()> {
        let file_name = self.0.join(team_id.to_string());
        remove_file(file_name)
            .await
            .context("could not remove seed id file")?;

        Ok(())
    }

    pub(crate) async fn list(&self) -> Result<Vec<(TeamId, PskSeedId)>> {
        let mut entries = read_dir(&self.0).await?;
        let mut out = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let team_id = TeamId::decode(entry.file_name().as_encoded_bytes())?;
            let seed_id = Self::read_id(entry.path()).await?;
            out.push((team_id, seed_id));
        }

        Ok(out)
    }

    async fn read_id(path: PathBuf) -> Result<PskSeedId> {
        const ID_SIZE: usize = size_of::<PskSeedId>();
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

pub(crate) async fn load_team_psk_pairs(
    eng: &mut CE,
    store: &mut LocalStore<KS>,
    dir: &SeedDir,
) -> Result<Vec<(TeamId, Arc<PresharedKey>)>> {
    let pairs = dir.list().await?;
    let mut out = Vec::new();

    for (team_id, seed_id) in pairs {
        let Some(seed) = qs::PskSeed::load(eng, store, &seed_id)? else {
            continue;
        };

        for psk in seed.generate_psks(team_id) {
            let psk = psk?;
            out.push((team_id, Arc::new(psk)));
        }
    }

    Ok(out)
}

// TODO(eric): Add a blanket impl for `Clone`?
pub trait TryClone: Sized {
    type Error: fmt::Display + fmt::Debug + error::Error + Send + Sync + 'static;

    fn try_clone(&self) -> Result<Self, Self::Error>;
}

impl TryClone for fs_keystore::Store {
    type Error = fs_keystore::Error;

    fn try_clone(&self) -> Result<Self, Self::Error> {
        fs_keystore::Store::try_clone(self)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use anyhow::Context as _;
    use aranya_crypto::{id::IdExt, Rng};
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
            let team_id = TeamId::random(&mut Rng);
            let seed_id = PskSeedId::random(&mut Rng);

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

    #[test(tokio::test(flavor = "multi_thread"))]
    async fn test_append_and_remove() -> Result<()> {
        let tmp_dir = tempdir()?;
        let path = tmp_dir.path().join("seeds");

        let seed_dir = SeedDir::new(path)
            .await
            .context("could not create seed dir")?;

        for _ in 0..100 {
            let team_id = TeamId::random(&mut Rng);
            let seed_id = PskSeedId::random(&mut Rng);

            seed_dir
                .append(&team_id, &seed_id)
                .await
                .context("could not append")?;

            assert!(seed_dir.remove(&team_id).await.is_ok())
        }

        Ok(())
    }
}
