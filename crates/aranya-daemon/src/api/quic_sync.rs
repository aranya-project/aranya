use std::sync::Arc;

use aranya_daemon_api::{AddSeedMode, CreateSeedMode, CreateTeamQuicSyncConfig};

use super::*;
use crate::sync::transport::quic::PskStore;

/// Held by [`super::DaemonApiServer`] when the QUIC syncer is used
#[derive(Debug)]
pub(crate) struct Data {
    pub(crate) psk_store: Arc<PskStore>,
}

impl Api {
    pub(super) async fn create_team_quic_sync(
        &mut self,
        team_id: api::TeamId,
        qs_cfg: CreateTeamQuicSyncConfig,
    ) -> api::Result<()> {
        let psk_store = self
            .quic
            .as_ref()
            .context("quic syncing is not enabled")?
            .psk_store
            .clone();

        let seed = match &qs_cfg.seed_mode {
            CreateSeedMode::Generate => qs::PskSeed::new(&mut Rng, team_id),
            CreateSeedMode::IKM(ikm) => qs::PskSeed::import_from_ikm(ikm, team_id),
        };

        self.add_seed(team_id, seed.clone()).await?;

        for psk_res in seed.generate_psks(team_id) {
            let psk = psk_res.context("unable to generate psk")?;
            psk_store.insert(team_id, Arc::new(psk));
        }

        Ok(())
    }

    pub(super) async fn add_team_quic_sync(
        &mut self,
        team: api::TeamId,
        cfg: api::AddTeamQuicSyncConfig,
    ) -> api::Result<()> {
        let psk_store = self
            .quic
            .as_ref()
            .context("quic syncing is not enabled")?
            .psk_store
            .clone();

        let seed = match cfg.seed_mode {
            AddSeedMode::IKM(ikm) => qs::PskSeed::import_from_ikm(&ikm, team),
            AddSeedMode::Wrapped(wrapped) => {
                let enc_sk: EncryptionKey<CS> = {
                    let enc_id = self.pk.lock().expect("poisoned").enc_pk.id()?;
                    let crypto = &mut *self.crypto.lock().await;
                    crypto
                        .aranya_store
                        .get_key(&mut crypto.engine, enc_id)
                        .context("keystore error")?
                        .context("missing enc_sk in add_team")?
                };

                let group = GroupId::transmute(team);
                let seed = enc_sk
                    .open_psk_seed(
                        &wrapped.encap_key,
                        wrapped.encrypted_seed,
                        &wrapped.sender_pk,
                        &group,
                    )
                    .context("could not open psk seed")?;
                qs::PskSeed(seed)
            }
        };

        self.add_seed(team, seed.clone()).await?;

        for psk_res in seed.generate_psks(team) {
            let psk = psk_res.context("unable to generate psk")?;
            psk_store.insert(team, Arc::new(psk));
        }

        Ok(())
    }

    pub(super) fn remove_team_quic_sync(
        &self,
        team: api::TeamId,
        data: &Data,
    ) -> anyhow::Result<()> {
        data.psk_store.remove(team);
        Ok(())
    }
}
