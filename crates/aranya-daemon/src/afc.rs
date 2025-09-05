//! Implementation of daemon's AFC handler.

use std::{
    fmt::Debug,
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
};

use anyhow::{anyhow, Context, Result};
use aranya_afc_util::{
    BidiChannelCreated, BidiChannelReceived, BidiKeys, Handler, UniChannelCreated,
    UniChannelReceived,
};
use aranya_crypto::{
    afc::{RawOpenKey, RawSealKey},
    CipherSuite, DeviceId, Engine, KeyStore, Rng,
};
use aranya_fast_channels::{
    shm::{self, Flag, Mode, WriteState},
    AranyaState, ChannelId, Directed,
};
use buggy::bug;
use derive_where::derive_where;
use tokio::sync::Mutex;
use tracing::{debug, info, instrument};

use crate::{
    config::AfcConfig,
    keystore::AranyaStore,
    policy::{
        AfcBidiChannelCreated, AfcBidiChannelReceived, AfcUniChannelCreated, AfcUniChannelReceived,
    },
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
        // TODO: issue stellar-tapestry#34
        // afc::shm{ReadState, WriteState} doesn't work on linux/arm64
        debug!(shm_path = cfg.shm_path, "setting up afc shm write side");
        let write = {
            let path = aranya_util::ShmPathBuf::from_str(&cfg.shm_path)
                .context("unable to parse AFC shared memory path")?;
            if cfg.unlink_on_startup && cfg.create {
                let _ = shm::unlink(&path);
            }
            WriteState::open(&path, Flag::Create, Mode::ReadWrite, cfg.max_chans, Rng)
                .context(format!("unable to open `WriteState`: {:?}", cfg.shm_path))?
        };

        Ok(Self { cfg, write })
    }
}

impl<E> Drop for AfcShm<E> {
    fn drop(&mut self) {
        {
            if self.cfg.unlink_at_exit {
                if let Ok(path) = aranya_util::shm::ShmPathBuf::from_str(&self.cfg.shm_path) {
                    let _ = shm::unlink(path);
                }
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
    /// Channel ID counter.
    channel_id: AtomicU32,
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
        Ok(Self {
            device_id,
            handler: Mutex::new(Handler::new(device_id, store)),
            eng: Mutex::new(eng),
            channel_id: AtomicU32::new(0),
            shm: Mutex::new(AfcShm::new(cfg)?),
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
    /// Handles the [`AfcBidiChannelCreated`] effect, returning
    /// the channel ID.
    #[instrument(skip_all, fields(id = %e.author_enc_key_id))]
    pub(crate) async fn bidi_channel_created(&self, e: &AfcBidiChannelCreated) -> Result<ChannelId>
    where
        E: Engine<CS = C>,
    {
        if e.author_id != self.device_id.into() {
            bug!("not the author of the bidi channel");
        }

        let info = BidiChannelCreated {
            key_id: e.channel_key_id.into(),
            parent_cmd_id: e.parent_cmd_id.into(),
            author_id: e.author_id.into(),
            author_enc_key_id: e.author_enc_key_id.into(),
            peer_id: e.peer_id.into(),
            peer_enc_pk: &e.peer_enc_pk,
            label_id: e.label_id.into(),
        };
        info!("handling create bidi channel");
        let keys: BidiKeys<RawSealKey<<E as Engine>::CS>, RawOpenKey<<E as Engine>::CS>> = self
            .while_locked(|handler, eng| handler.bidi_channel_created(eng, &info))
            .await?;
        let channel_id = self.channel_id.fetch_add(1, Ordering::Relaxed);
        info!(?channel_id, "creating bidi channel");
        self.shm
            .lock()
            .await
            .write
            .add(
                channel_id.into(),
                Directed::Bidirectional {
                    seal: keys.seal,
                    open: keys.open,
                },
                info.label_id,
            )
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;
        Ok(channel_id.into())
    }

    /// Handles the [`AfcBidiChannelReceived`] effect, returning
    /// the channel ID.
    #[instrument(skip_all, fields(id = %e.label_id))]
    pub(crate) async fn bidi_channel_received(
        &self,
        e: &AfcBidiChannelReceived,
    ) -> Result<ChannelId>
    where
        E: Engine<CS = C>,
    {
        if e.peer_id != self.device_id.into() {
            bug!("not the peer of the bidi channel");
        }

        let info = BidiChannelReceived {
            parent_cmd_id: e.parent_cmd_id.into(),
            author_id: e.author_id.into(),
            author_enc_pk: &e.author_enc_pk,
            peer_id: e.peer_id.into(),
            peer_enc_key_id: e.peer_enc_key_id.into(),
            label_id: e.label_id.into(),
            encap: &e.encap,
        };
        let BidiKeys { seal, open } = self
            .while_locked(|handler, eng| handler.bidi_channel_received(eng, &info))
            .await?;
        let channel_id = self.channel_id.fetch_add(1, Ordering::Relaxed);
        info!(?channel_id, "receiving bidi channel");
        self.shm
            .lock()
            .await
            .write
            .add(
                channel_id.into(),
                Directed::Bidirectional { seal, open },
                info.label_id,
            )
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;

        Ok(channel_id.into())
    }

    /// Handles the [`AfcUniChannelCreated`] effect, returning
    /// the channel ID.
    #[instrument(skip_all, fields(id = %e.author_enc_key_id))]
    pub(crate) async fn uni_channel_created(&self, e: &AfcUniChannelCreated) -> Result<ChannelId>
    where
        E: Engine<CS = C>,
    {
        if e.author_id != self.device_id.into() {
            bug!("not the author of the uni channel");
        }
        if e.sender_id != self.device_id.into() && e.receiver_id != self.device_id.into() {
            bug!("not a member of this uni channel");
        }

        let info = UniChannelCreated {
            key_id: e.channel_key_id.into(),
            parent_cmd_id: e.parent_cmd_id.into(),
            author_id: e.author_id.into(),
            author_enc_key_id: e.author_enc_key_id.into(),
            seal_id: e.sender_id.into(),
            open_id: e.receiver_id.into(),
            peer_enc_pk: &e.peer_enc_pk,
            label_id: e.label_id.into(),
        };
        let key = self
            .while_locked(|handler, eng| handler.uni_channel_created(eng, &info))
            .await?;
        let channel_id = self.channel_id.fetch_add(1, Ordering::Relaxed);
        info!(?channel_id, "creating uni channel");
        self.shm
            .lock()
            .await
            .write
            .add(channel_id.into(), key.into(), info.label_id)
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;
        Ok(channel_id.into())
    }

    /// Handles the [`AfcUniChannelReceived`] effect, returning
    /// the channel ID.
    #[instrument(skip_all, fields(id = %e.label_id))]
    pub(crate) async fn uni_channel_received(&self, e: &AfcUniChannelReceived) -> Result<ChannelId>
    where
        E: Engine<CS = C>,
    {
        if e.author_id == self.device_id.into() {
            bug!("not the peer of the uni channel");
        }
        if e.sender_id != self.device_id.into() && e.receiver_id != self.device_id.into() {
            bug!("not a member of this uni channel");
        }

        let info = UniChannelReceived {
            parent_cmd_id: e.parent_cmd_id.into(),
            seal_id: e.sender_id.into(),
            open_id: e.receiver_id.into(),
            author_id: e.author_id.into(),
            author_enc_pk: &e.author_enc_pk,
            peer_enc_key_id: e.peer_enc_key_id.into(),
            label_id: e.label_id.into(),
            encap: &e.encap,
        };
        let key = self
            .while_locked(|handler, eng| handler.uni_channel_received(eng, &info))
            .await?;
        let channel_id = self.channel_id.fetch_add(1, Ordering::Relaxed);
        info!(?channel_id, "receiving uni channel");
        self.shm
            .lock()
            .await
            .write
            .add(channel_id.into(), key.into(), info.label_id)
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;
        Ok(channel_id.into())
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
}
