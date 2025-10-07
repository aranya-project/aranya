//! Implementation of daemon's AFC handler.

use std::fmt::Debug;

use anyhow::{anyhow, Context, Result};
use aranya_afc_util::{Handler, UniChannelCreated, UniChannelReceived};
use aranya_crypto::{CipherSuite, DeviceId, Engine, KeyStore, Rng};
use aranya_daemon_api::{self as api};
use aranya_fast_channels::{
    shm::{Flag, Mode, WriteState},
    AranyaState, ChannelId,
};
use derive_where::derive_where;
use tokio::sync::Mutex;
use tracing::{debug, instrument, warn};

use crate::{
    config::AfcConfig,
    keystore::AranyaStore,
    policy::{AfcUniChannelCreated, AfcUniChannelReceived},
};

/// AFC shared memory.
pub struct AfcShm<C> {
    cfg: AfcConfig,
    write: WriteState<C, Rng>,
}

impl<C> AfcShm<C>
where
    C: CipherSuite,
{
    fn new(cfg: AfcConfig) -> Result<Self> {
        debug!("setting up afc shm write side: {:?}", cfg.shm_path);
        // TODO: check if shm path exists first?
        let open_res = WriteState::open(
            cfg.shm_path.clone(),
            Flag::Create,
            Mode::ReadWrite,
            cfg.max_chans,
            Rng,
        )
        .with_context(|| format!("unable to create new `WriteState`: {:?}", cfg.shm_path));
        match open_res {
            Ok(w) => Ok(Self { cfg, write: w }),
            Err(e) => {
                warn!(?e);
                let w = WriteState::open(
                    cfg.shm_path.clone(),
                    Flag::OpenOnly,
                    Mode::ReadWrite,
                    cfg.max_chans,
                    Rng,
                )
                .with_context(|| {
                    format!("unable to open existing `WriteState`: {:?}", cfg.shm_path)
                })?;

                Ok(Self { cfg, write: w })
            }
        }
    }
}

impl<E> Debug for AfcShm<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: debug write field.
        f.debug_struct("AfcShm").field("cfg", &self.cfg).finish()
    }
}

#[derive_where(Debug)]
pub(crate) struct Afc<E, C, KS> {
    /// Our device ID.
    device_id: DeviceId,
    #[derive_where(skip(Debug))]
    handler: Mutex<Handler<AranyaStore<KS>>>,
    #[derive_where(skip(Debug))]
    eng: Mutex<E>,
    /// AFC shared memory.
    shm: Mutex<AfcShm<C>>,
}

impl<E, C, KS> Afc<E, C, KS> {
    pub(crate) fn new(
        eng: E,
        device_id: DeviceId,
        store: AranyaStore<KS>,
        cfg: AfcConfig,
    ) -> Result<Self>
    where
        E: Engine,
        C: CipherSuite,
    {
        let shm = AfcShm::new(cfg)?;
        Ok(Self {
            device_id,
            handler: Mutex::new(Handler::new(device_id, store)),
            eng: Mutex::new(eng),
            shm: Mutex::new(shm),
        })
    }

    async fn while_locked<'a, F, R>(&'a self, f: F) -> R
    where
        F: for<'b> FnOnce(&'b mut Handler<AranyaStore<KS>>, &'b mut E) -> R,
    {
        let mut handler = self.handler.lock().await;
        let mut eng = self.eng.lock().await;
        f(&mut *handler, &mut *eng)
    }
}

impl<E, C, KS> Afc<E, C, KS>
where
    E: Engine,
    C: CipherSuite,
    KS: KeyStore,
{
    /// Handles the [`AfcUniChannelCreated`] effect, returning
    /// the channel ID.
    #[instrument(skip_all, fields(id = %e.author_enc_key_id))]
    pub(crate) async fn uni_channel_created(&self, e: &AfcUniChannelCreated) -> Result<ChannelId>
    where
        E: Engine<CS = C>,
    {
        let info = UniChannelCreated {
            key_id: e.channel_key_id.into(),
            parent_cmd_id: e.parent_cmd_id.into(),
            author_id: self.device_id,
            author_enc_key_id: e.author_enc_key_id.into(),
            seal_id: self.device_id,
            open_id: e.receiver_id.into(),
            peer_enc_pk: &e.peer_enc_pk,
            label_id: e.label_id.into(),
        };
        let key = self
            .while_locked(|handler, eng| handler.uni_channel_created(eng, &info))
            .await?;
        let channel_id = self
            .shm
            .lock()
            .await
            .write
            .add(key.into(), info.label_id)
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;
        debug!(?channel_id, "creating uni channel");
        Ok(channel_id)
    }

    /// Handles the [`AfcUniChannelReceived`] effect, returning
    /// the channel ID.
    #[instrument(skip_all, fields(id = %e.label_id))]
    pub(crate) async fn uni_channel_received(&self, e: &AfcUniChannelReceived) -> Result<ChannelId>
    where
        E: Engine<CS = C>,
    {
        let info = UniChannelReceived {
            parent_cmd_id: e.parent_cmd_id.into(),
            seal_id: e.sender_id.into(),
            open_id: self.device_id,
            author_id: e.sender_id.into(),
            author_enc_pk: &e.author_enc_pk,
            peer_enc_key_id: e.peer_enc_key_id.into(),
            label_id: e.label_id.into(),
            encap: &e.encap,
        };
        let key = self
            .while_locked(|handler, eng| handler.uni_channel_received(eng, &info))
            .await?;
        let channel_id = self
            .shm
            .lock()
            .await
            .write
            .add(key.into(), info.label_id)
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;
        debug!(?channel_id, "receiving uni channel");

        Ok(channel_id)
    }

    pub(crate) async fn delete_channel(&self, channel_id: ChannelId) -> Result<()>
    where
        E: Engine<CS = C>,
    {
        self.shm
            .lock()
            .await
            .write
            .remove(channel_id)
            .map_err(|err| anyhow!("unable to remove AFC channel: {err}"))
    }

    pub(crate) async fn get_shm_info(&self) -> api::AfcShmInfo {
        let shm = self.shm.lock().await;
        api::AfcShmInfo {
            path: shm.cfg.shm_path.clone(),
            max_chans: shm.cfg.max_chans,
        }
    }
}
