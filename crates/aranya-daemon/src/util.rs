use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use aranya_crypto::{Engine, Id, KeyStore};
use aranya_daemon_api::{QuicSyncSeed, QuicSyncSeedId, TeamId};
use s2n_quic::provider::tls::rustls::rustls::crypto::{hash::HashAlgorithm, PresharedKey};
use tokio::{
    fs::File,
    io::{AsyncReadExt as _, AsyncWriteExt},
};

use crate::{CE, CS, KS};

pub(crate) struct SeedFile(File);

const ID_SIZE: usize = const { size_of::<Id>() };

impl SeedFile {
    pub(crate) async fn new<P: AsRef<Path>>(p: P) -> Result<Self> {
        let f = File::options()
            .append(true)
            .write(true)
            .create(true)
            .open(p)
            .await?;
        Ok(Self(f))
    }

    pub(crate) async fn append(
        &mut self,
        team_id: &TeamId,
        seed_id: &QuicSyncSeedId,
    ) -> Result<()> {
        let combined = [team_id.as_bytes(), seed_id.as_bytes()].concat(); // call write twice instead?
        self.0
            .write_all(&combined)
            .await
            .context("could not write seed ID to file")?;

        self.0.flush().await.context("could not flush to seed file")
    }

    async fn list(&mut self) -> Result<Vec<(TeamId, QuicSyncSeedId)>> {
        let mut buf = [0; ID_SIZE * 2];
        let mut out = Vec::new();

        loop {
            match self.0.read_exact(&mut buf).await {
                Ok(read) => {
                    tracing::debug!(read);
                    debug_assert_eq!(read, ID_SIZE * 2);

                    let team_id = {
                        let arr: [u8; ID_SIZE] = buf[0..ID_SIZE].try_into()?;
                        TeamId::from(arr)
                    };
                    let seed_id = {
                        let arr: [u8; ID_SIZE] = buf[ID_SIZE..].try_into()?;
                        QuicSyncSeedId::from(arr)
                    };
                    out.push((team_id, seed_id));
                }
                Err(e) => {
                    tracing::debug!(%e);
                    break;
                }
            }
        }

        Ok(out)
    }
}

fn load_seed(
    eng: &mut CE,
    store: &mut KS,
    id: &QuicSyncSeedId,
) -> Result<Option<QuicSyncSeed<CS>>> {
    let Some(wrapped) = store.get(id.into_id())? else {
        return Ok(None);
    };
    let seed = eng.unwrap(&wrapped)?;

    Ok(Some(seed))
}

pub(crate) async fn load_team_psk_pairs(
    eng: &mut CE,
    store: &mut KS,
    file: &mut SeedFile,
) -> Result<Vec<(TeamId, Arc<PresharedKey>)>> {
    let pairs = file.list().await?;
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
    use aranya_crypto::Rng;
    use tempfile::tempdir;
    use test_log::test;

    use super::*;

    #[test(tokio::test(flavor = "multi_thread"))]
    #[ignore = "fix bad file descriptor"]
    async fn test_append() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("seeds");

        let mut seed_file = SeedFile::new(path).await?;
        let team_id = Id::random(&mut Rng).into();
        let seed_id = Id::random(&mut Rng).into();

        seed_file.append(&team_id, &seed_id).await?;

        let out = seed_file.list().await?;

        assert_eq!(out, vec![(team_id, seed_id)]);

        Ok(())
    }
}
