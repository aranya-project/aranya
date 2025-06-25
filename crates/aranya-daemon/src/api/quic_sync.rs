use std::sync::Arc;

use aranya_daemon_api::QuicSyncConfig;

use super::*;
use crate::sync::task::quic::PskStore;

/// Held by [`super::DaemonApiServer`] when the QUIC syncer is used
#[derive(Debug)]
pub(crate) struct Data {
    pub(crate) psk_store: Arc<PskStore>,
}

impl Api {
    pub(super) async fn create_team_quic_sync(
        &mut self,
        team_id: api::TeamId,
        qs_cfg: QuicSyncConfig,
    ) -> api::Result<()> {
        let psk_store = self
            .quic
            .as_ref()
            .context("quic syncing is not enabled")?
            .psk_store
            .clone();

        let seed = match &qs_cfg.seed_mode {
            SeedMode::Generate => qs::PskSeed::new(&mut Rng, team_id),
            SeedMode::IKM(ikm) => qs::PskSeed::import_from_ikm(ikm, team_id),
            SeedMode::Wrapped { .. } => {
                return Err(api::Error::from_msg(
                    "Cannot create team with existing wrapped PSK seed",
                ))
            }
        };

        self.add_seed(team_id, seed.clone()).await?;

        for psk_res in seed.generate_psks(team_id) {
            let psk = psk_res.context("unable to generate psk")?;
            psk_store
                .insert(team_id, Arc::new(psk))
                .inspect_err(|err| error!(err = ?err, "unable to insert PSK"))?
        }

        Ok(())
    }

    pub(super) async fn add_team_quic_sync(
        &mut self,
        team: api::TeamId,
        cfg: QuicSyncConfig,
    ) -> api::Result<()> {
        let psk_store = self
            .quic
            .as_ref()
            .context("quic syncing is not enabled")?
            .psk_store
            .clone();

        let seed = match cfg.seed_mode {
            SeedMode::Generate => {
                return Err(api::Error::from_msg(
                    "Must provide PSK seed from team creation",
                ));
            }
            SeedMode::IKM(ikm) => qs::PskSeed::import_from_ikm(&ikm, team),
            SeedMode::Wrapped(wrapped) => {
                let enc_sk: EncryptionKey<CS> = {
                    let enc_id = self.pk.lock().expect("poisoned").enc_pk.id()?;
                    let crypto = &mut *self.crypto.lock().await;
                    crypto
                        .aranya_store
                        .get_key(&mut crypto.engine, enc_id.into_id())
                        .context("keystore error")?
                        .context("missing enc_sk in add_team")?
                };

                let group = GroupId::from(team.into_id());
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
            psk_store
                .insert(team, Arc::new(psk))
                .inspect_err(|err| error!(err = ?err, "unable to insert PSK"))?
        }

        Ok(())
    }

    pub(super) fn remove_team_quic_sync(
        &self,
        team: api::TeamId,
        data: &Data,
    ) -> anyhow::Result<()> {
        data.psk_store
            .remove(team)
            .inspect_err(|err| error!(err = ?err, "unable to remove PSK"))?;

        Ok(())
    }
}
