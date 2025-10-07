#![cfg(feature = "aqc")]
#![cfg_attr(docsrs, doc(cfg(feature = "aqc")))]
//! Implementation of daemon's AQC handler.
use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use aranya_aqc_util::{
    BidiChannelCreated, BidiChannelReceived, Handler, UniChannelCreated, UniChannelReceived,
};
use aranya_crypto::{DeviceId, Engine, KeyStore};
use aranya_daemon_api::{
    AqcBidiPsk, AqcBidiPsks, AqcPsks, AqcUniPsk, AqcUniPsks, Directed, NetIdentifier, Secret,
};
use aranya_runtime::GraphId;
use bimap::BiBTreeMap;
use buggy::{bug, BugExt};
use derive_where::derive_where;
use tokio::sync::Mutex;
use tracing::{debug, instrument};

use crate::{
    keystore::AranyaStore,
    policy::{
        AqcBidiChannelCreated, AqcBidiChannelReceived, AqcUniChannelCreated, AqcUniChannelReceived,
    },
};

type PeerMap = BTreeMap<GraphId, Peers>;
type Peers = BiBTreeMap<NetIdentifier, DeviceId>;

#[derive_where(Debug)]
pub(crate) struct Aqc<E, KS> {
    /// Our device ID.
    device_id: DeviceId,
    /// All the peers that we have channels with.
    peers: Arc<Mutex<PeerMap>>,
    #[derive_where(skip(Debug))]
    handler: Mutex<Handler<AranyaStore<KS>>>,
    #[derive_where(skip(Debug))]
    eng: Mutex<E>,
}

impl<E, KS> Aqc<E, KS> {
    pub(crate) fn new<I>(eng: E, device_id: DeviceId, store: AranyaStore<KS>, peers: I) -> Self
    where
        I: IntoIterator<Item = (GraphId, Peers)>,
    {
        Self {
            device_id,
            peers: Arc::new(Mutex::new(PeerMap::from_iter(peers))),
            handler: Mutex::new(Handler::new(device_id, store)),
            eng: Mutex::new(eng),
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

impl<E, KS> Aqc<E, KS>
where
    E: Engine,
    KS: KeyStore,
{
    /// Handles the [`AqcBidiChannelCreated`] effect, returning
    /// the channel's PSKs.
    #[instrument(skip_all, fields(id = %e.channel_id))]
    pub(crate) async fn bidi_channel_created(
        &self,
        e: &AqcBidiChannelCreated,
    ) -> Result<AqcBidiPsks> {
        if e.author_id != self.device_id.into() {
            bug!("not the author of the bidi channel");
        }

        let info = BidiChannelCreated {
            parent_cmd_id: e.parent_cmd_id.into(),
            author_id: e.author_id.into(),
            author_enc_key_id: e.author_enc_key_id.into(),
            peer_id: e.peer_id.into(),
            peer_enc_pk: &e.peer_enc_pk,
            label_id: e.label_id.into(),
            channel_id: e.channel_id.into(),
            author_secrets_id: e.author_secrets_id.into(),
            psk_length_in_bytes: u16::try_from(e.psk_length_in_bytes)
                .assume("`psk_length_in_bytes` is out of range")?,
        };
        let secret = self
            .while_locked(|handler, eng| handler.bidi_channel_created(eng, &info))
            .await?;
        debug_assert_eq!(e.channel_id, (*secret.id()).into());

        AqcBidiPsks::try_from_fn(info.channel_id, |suite| {
            secret.generate_psk(suite).map(|psk| AqcBidiPsk {
                identity: *psk.identity(),
                secret: Secret::from(psk.raw_secret_bytes()),
            })
        })
    }

    /// Handles the [`AqcBidiChannelReceived`] effect, returning
    /// the channel's PSKs.
    #[instrument(skip_all, fields(id = %e.channel_id))]
    pub(crate) async fn bidi_channel_received(
        &self,
        e: &AqcBidiChannelReceived,
    ) -> Result<AqcPsks> {
        if e.peer_id != self.device_id.into() {
            bug!("not the peer of the bidi channel");
        }

        let info = BidiChannelReceived {
            channel_id: e.channel_id.into(),
            parent_cmd_id: e.parent_cmd_id.into(),
            author_id: e.author_id.into(),
            author_enc_pk: &e.author_enc_pk,
            peer_id: e.peer_id.into(),
            peer_enc_key_id: e.peer_enc_key_id.into(),
            label_id: e.label_id.into(),
            encap: &e.encap,
            psk_length_in_bytes: u16::try_from(e.psk_length_in_bytes)
                .assume("`psk_length_in_bytes` is out of range")?,
        };
        let secret = self
            .while_locked(|handler, eng| handler.bidi_channel_received(eng, &info))
            .await?;
        debug_assert_eq!(e.channel_id, (*secret.id()).into());

        let psks = AqcBidiPsks::try_from_fn(info.channel_id, |suite| {
            secret.generate_psk(suite).map(|psk| AqcBidiPsk {
                identity: *psk.identity(),
                secret: Secret::from(psk.raw_secret_bytes()),
            })
        })?;
        Ok(AqcPsks::Bidi(psks))
    }

    /// Handles the [`AqcUniChannelCreated`] effect, returning
    /// the channel's PSKs.
    #[instrument(skip_all, fields(id = %e.channel_id))]
    pub(crate) async fn uni_channel_created(&self, e: &AqcUniChannelCreated) -> Result<AqcUniPsks> {
        if e.author_id != self.device_id.into() {
            bug!("not the author of the uni channel");
        }
        if e.sender_id != self.device_id.into() && e.receiver_id != self.device_id.into() {
            bug!("not a member of this uni channel");
        }

        let info = UniChannelCreated {
            parent_cmd_id: e.parent_cmd_id.into(),
            author_id: e.author_id.into(),
            author_enc_key_id: e.author_enc_key_id.into(),
            send_id: e.sender_id.into(),
            recv_id: e.receiver_id.into(),
            peer_enc_pk: &e.peer_enc_pk,
            label_id: e.label_id.into(),
            channel_id: e.channel_id.into(),
            author_secrets_id: e.author_secrets_id.into(),
            psk_length_in_bytes: u16::try_from(e.psk_length_in_bytes)
                .assume("`psk_length_in_bytes` is out of range")?,
        };
        let secret = self
            .while_locked(|handler, eng| handler.uni_channel_created(eng, &info))
            .await?;
        debug_assert_eq!(e.channel_id, (*secret.id()).into());

        let psks = AqcUniPsks::try_from_fn(info.channel_id, |suite| {
            if self.device_id == info.send_id {
                secret.generate_send_only_psk(suite).map(|psk| {
                    let identity = *psk.identity();
                    let secret = Directed::Send(Secret::from(psk.raw_secret_bytes()));
                    AqcUniPsk { identity, secret }
                })
            } else {
                secret.generate_recv_only_psk(suite).map(|psk| {
                    let identity = *psk.identity();
                    let secret = Directed::Recv(Secret::from(psk.raw_secret_bytes()));
                    AqcUniPsk { identity, secret }
                })
            }
        })?;
        Ok(psks)
    }

    /// Handles the [`AqcUniChannelReceived`] effect, returning
    /// the channel's PSKs.
    #[instrument(skip_all, fields(id = %e.channel_id))]
    pub(crate) async fn uni_channel_received(&self, e: &AqcUniChannelReceived) -> Result<AqcPsks> {
        if e.author_id == self.device_id.into() {
            bug!("not the peer of the uni channel");
        }
        if e.sender_id != self.device_id.into() && e.receiver_id != self.device_id.into() {
            bug!("not a member of this uni channel");
        }

        let info = UniChannelReceived {
            channel_id: e.channel_id.into(),
            parent_cmd_id: e.parent_cmd_id.into(),
            send_id: e.sender_id.into(),
            recv_id: e.receiver_id.into(),
            author_id: e.author_id.into(),
            author_enc_pk: &e.author_enc_pk,
            peer_enc_key_id: e.peer_enc_key_id.into(),
            label_id: e.label_id.into(),
            encap: &e.encap,
            psk_length_in_bytes: u16::try_from(e.psk_length_in_bytes)
                .assume("`psk_length_in_bytes` is out of range")?,
        };
        let secret = self
            .while_locked(|handler, eng| handler.uni_channel_received(eng, &info))
            .await?;
        debug_assert_eq!(e.channel_id, (*secret.id()).into());

        let psks = AqcUniPsks::try_from_fn(info.channel_id, |suite| {
            if self.device_id == info.send_id {
                secret.generate_send_only_psk(suite).map(|psk| {
                    let identity = *psk.identity();
                    let secret = Directed::Send(Secret::from(psk.raw_secret_bytes()));
                    AqcUniPsk { identity, secret }
                })
            } else {
                secret.generate_recv_only_psk(suite).map(|psk| {
                    let identity = *psk.identity();
                    let secret = Directed::Recv(Secret::from(psk.raw_secret_bytes()));
                    AqcUniPsk { identity, secret }
                })
            }
        })?;
        Ok(AqcPsks::Uni(psks))
    }
}
