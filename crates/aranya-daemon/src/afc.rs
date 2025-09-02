//! Implementation of daemon's AFC handler.

use std::{
    collections::BTreeMap,
    sync::{atomic::AtomicU32, Arc},
};

use anyhow::Result;
use aranya_afc_util::{
    BidiChannelCreated, BidiChannelReceived, BidiKeys, Handler, UniChannelCreated,
    UniChannelReceived, UniKey,
};
use aranya_crypto::{afc::UniAuthorSecret, DeviceId, Engine, KeyStore};
use aranya_daemon_api::{Directed, NetIdentifier, Secret};
use aranya_runtime::GraphId;
use bimap::BiBTreeMap;
use buggy::{bug, BugExt};
use derive_where::derive_where;
use tokio::sync::Mutex;
use tracing::{debug, instrument};

use crate::{
    keystore::AranyaStore,
    policy::{
        AfcBidiChannelCreated, AfcBidiChannelReceived, AfcUniChannelCreated, AfcUniChannelReceived,
    },
};

type PeerMap = BTreeMap<GraphId, Peers>;
type Peers = BiBTreeMap<NetIdentifier, DeviceId>;

/// AFC shared memory.
#[cfg(all(feature = "afc", feature = "unstable"))]
#[derive(Debug)]
pub struct AfcShm {
    cfg: AfcConfig,
    write: WriteState<CS, Rng>,
}

impl AfcShm {
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
                .context("unable to open `WriteState`")?
        };

        Ok(Self { cfg, write })
    }
}

impl Drop for AfcShm {
    fn drop(&mut self) {
        #[cfg(all(feature = "afc", feature = "unstable"))]
        {
            if self.cfg.unlink_at_exit {
                if let Ok(path) = aranya_util::util::ShmPathBuf::from_str(&self.cfg.shm_path) {
                    let _ = shm::unlink(path);
                }
            }
        }
    }
}

#[derive_where(Debug)]
pub(crate) struct Afc<E, KS> {
    /// Our device ID.
    device_id: DeviceId,
    /// All the peers that we have channels with.
    peers: Arc<Mutex<PeerMap>>,
    #[derive_where(skip(Debug))]
    handler: Mutex<Handler<AranyaStore<KS>>>,
    #[derive_where(skip(Debug))]
    eng: Mutex<E>,
    /// Channel ID counter.
    channel_id: AtomicU32,
    /// AFC shared memory.
    shm: AfcShm,
}

impl<E, KS> Afc<E, KS> {
    pub(crate) fn new<I>(
        eng: E,
        device_id: DeviceId,
        store: AranyaStore<KS>,
        peers: I,
        cfg: AfcConfig,
    ) -> Self
    where
        I: IntoIterator<Item = (GraphId, Peers)>,
    {
        Self {
            device_id,
            peers: Arc::new(Mutex::new(PeerMap::from_iter(peers))),
            handler: Mutex::new(Handler::new(device_id, store)),
            eng: Mutex::new(eng),
            channel_id: AtomicU32::new(0),
            shm: AfcShm::new(cfg),
        }
    }

    /// Returns the peer's device ID that corresponds to
    /// `net_id`.
    #[instrument(skip(self))]
    pub(crate) async fn find_device_id(&self, graph: GraphId, net_id: &str) -> Option<DeviceId> {
        debug!("looking for peer's device ID");

        self.peers
            .lock()
            .await
            .get(&graph)
            .and_then(|map| map.get_by_left(net_id))
            .copied()
    }

    /// Adds a peer.
    #[instrument(skip(self))]
    pub(crate) async fn add_peer(&self, graph: GraphId, net_id: NetIdentifier, id: DeviceId) {
        debug!("adding peer");

        self.peers
            .lock()
            .await
            .entry(graph)
            .or_default()
            .insert(net_id, id);
    }

    /// Removes a peer.
    #[instrument(skip(self))]
    pub(crate) async fn remove_peer(&self, graph: GraphId, id: DeviceId) {
        debug!("removing peer");

        self.peers.lock().await.entry(graph).and_modify(|entry| {
            entry.remove_by_right(&id);
        });
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

impl<E, KS> Afc<E, KS>
where
    E: Engine,
    KS: KeyStore,
{
    /// Handles the [`AfcBidiChannelCreated`] effect, returning
    /// the channel's PSKs.
    #[instrument(skip_all, fields(id = %e.channel_id))]
    pub(crate) async fn bidi_channel_created(&self, e: &AfcBidiChannelCreated) -> Result<()> {
        if e.author_id != self.device_id.into() {
            bug!("not the author of the bidi channel");
        }

        let info = BidiChannelCreated {
            key_id: e.author_enc_key_id,
            parent_cmd_id: e.parent_cmd_id,
            author_id: e.author_id.into(),
            author_enc_key_id: e.author_enc_key_id.into(),
            peer_id: e.peer_id.into(),
            peer_enc_pk: &e.peer_enc_pk,
            label_id: e.label_id.into(),
        };
        let BidiKeys { seal, open } = self
            .while_locked(|handler, eng| handler.bidi_channel_created(eng, &info))
            .await?;
        let channel_id = self.channel_id.fetch_add(1, Ordering::Relaxed);
        self.shm
            .lock()
            .await
            .add(channel_id, Directed::Bidirectional { seal, open })
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;
    }

    /// Handles the [`AfcBidiChannelReceived`] effect, returning
    /// the channel's PSKs.
    #[instrument(skip_all, fields(id = %e.channel_id))]
    pub(crate) async fn bidi_channel_received(&self, e: &AfcBidiChannelReceived) -> Result<()> {
        if e.peer_id != self.device_id.into() {
            bug!("not the peer of the bidi channel");
        }

        let info = BidiChannelReceived {
            parent_cmd_id: e.parent_cmd_id,
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
        self.shm
            .lock()
            .await
            .add(channel_id, Directed::Bidirectional { seal, open })
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;

        Ok(())
    }

    /// Handles the [`AfcUniChannelCreated`] effect, returning
    /// the channel's PSKs.
    #[instrument(skip_all, fields(id = %e.channel_id))]
    pub(crate) async fn uni_channel_created(&self, e: &AfcUniChannelCreated) -> Result<()> {
        if e.author_id != self.device_id.into() {
            bug!("not the author of the uni channel");
        }
        if e.sender_id != self.device_id.into() && e.receiver_id != self.device_id.into() {
            bug!("not a member of this uni channel");
        }

        let info = UniChannelCreated {
            key_id: e.author_enc_key_id,
            parent_cmd_id: e.parent_cmd_id,
            author_id: e.author_id.into(),
            author_enc_key_id: e.author_enc_key_id.into(),
            seal_id: e.sender_id.into(),
            open_id: e.receiver_id.into(),
            peer_enc_pk: &e.peer_enc_pk,
            label_id: e.label_id.into(),
        };
        let key: UniKey = self
            .while_locked(|handler, eng| handler.uni_channel_created(eng, &info))
            .await?;
        let channel_id = self.channel_id.fetch_add(1, Ordering::Relaxed);

        let secret = UniKey::try_from_fn(info.key_id, |suite| {
            if self.device_id == info.seal_id {
                Directed::Send(key);
            } else {
                Directed::Recv(key);
            }
        })?;
        self.shm
            .lock()
            .await
            .add(channel_id, secret)
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;
        Ok(())
    }

    /// Handles the [`AfcUniChannelReceived`] effect, returning
    /// the channel's PSKs.
    #[instrument(skip_all, fields(id = %e.channel_id))]
    pub(crate) async fn uni_channel_received(&self, e: &AfcUniChannelReceived) -> Result<()> {
        if e.author_id == self.device_id.into() {
            bug!("not the peer of the uni channel");
        }
        if e.sender_id != self.device_id.into() && e.receiver_id != self.device_id.into() {
            bug!("not a member of this uni channel");
        }

        let info = UniChannelReceived {
            parent_cmd_id: e.parent_cmd_id,
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

        let secret = UniKey::try_from_fn(info.key_id, |suite| {
            if self.device_id == info.seal_id {
                Directed::Send(key);
            } else {
                Directed::Recv(key);
            }
        })?;
        self.shm
            .lock()
            .await
            .add(channel_id, secret)
            .map_err(|err| anyhow!("unable to add AFC channel: {err}"))?;
        Ok(())
    }
}
