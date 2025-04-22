use core::{fmt, future::Future};
use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use aranya_aqc_util::Handler;
pub(crate) use aranya_aqc_util::{
    BidiChannelCreated, BidiChannelReceived, UniChannelCreated, UniChannelReceived,
};
use aranya_crypto::{DeviceId, Engine, KeyStore};
use aranya_daemon_api::{AqcBidiPsk, AqcUniPsk, Directed, NetIdentifier, Secret};
use aranya_runtime::GraphId;
use bimap::BiBTreeMap;
use tokio::sync::{Mutex, MutexGuard};

/// A mapping of `Net ID <=> Device ID`, separated by `Graph ID`.
type PeerMap = Arc<Mutex<BTreeMap<GraphId, Peers>>>;
type Peers = BiBTreeMap<NetIdentifier, DeviceId>;

pub(crate) struct Aqc<E, KS> {
    device_id: DeviceId,
    peers: PeerMap,
    handler: Mutex<Handler<KS>>,
    eng: Mutex<E>,
}

impl<E, KS> Aqc<E, KS> {
    pub(crate) fn new<I>(eng: E, device_id: DeviceId, store: KS, peers: I) -> Self
    where
        I: IntoIterator<Item = (GraphId, Peers)>,
    {
        Self {
            device_id,
            peers: Arc::new(Mutex::new(BTreeMap::from_iter(peers))),
            handler: Mutex::new(Handler::new(device_id, store)),
            eng: Mutex::new(eng),
        }
    }

    pub(crate) async fn find_peer(&self, graph: GraphId, net_id: &str) -> Option<DeviceId> {
        self.peers
            .lock()
            .await
            .get(&graph)
            .and_then(|map| map.get_by_left(net_id))
            .copied()
    }

    pub(crate) async fn find_net_id(&self, graph: GraphId, id: DeviceId) -> Option<NetIdentifier> {
        self.peers
            .lock()
            .await
            .get(&graph)
            .and_then(|map| map.get_by_right(&id))
            .cloned()
    }

    pub(crate) async fn add_peer(&self, graph: GraphId, net_id: NetIdentifier, id: DeviceId) {
        self.peers
            .lock()
            .await
            .entry(graph)
            .or_default()
            .insert(net_id, id);
    }

    async fn while_locked<'a, F, Fut, R>(&'a self, f: F) -> R
    where
        F: FnOnce(MutexGuard<'a, Handler<KS>>, MutexGuard<'a, E>) -> Fut,
        Fut: Future<Output = R>,
    {
        let handler = self.handler.lock().await;
        let eng = self.eng.lock().await;
        f(handler, eng).await
    }
}

impl<E, KS> Aqc<E, KS>
where
    E: Engine,
    KS: KeyStore,
{
    pub(crate) async fn bidi_channel_created(
        &self,
        info: &BidiChannelCreated<'_>,
    ) -> Result<AqcBidiPsk> {
        let psk = self
            .while_locked(|mut handler, mut eng| async move {
                handler.bidi_channel_created(&mut *eng, info)
            })
            .await?;
        Ok(AqcBidiPsk {
            identity: psk.identity().into(),
            secret: Secret::from(psk.raw_secret_bytes()),
        })
    }

    pub(crate) async fn bidi_channel_received(
        &self,
        info: &BidiChannelReceived<'_>,
    ) -> Result<AqcBidiPsk> {
        let psk = self
            .while_locked(|mut handler, mut eng| async move {
                handler.bidi_channel_received(&mut *eng, info)
            })
            .await?;
        Ok(AqcBidiPsk {
            identity: psk.identity().into(),
            secret: Secret::from(psk.raw_secret_bytes()),
        })
    }

    pub(crate) async fn uni_channel_created(
        &self,
        info: &UniChannelCreated<'_>,
    ) -> Result<AqcUniPsk> {
        let psk = self
            .while_locked(|mut handler, mut eng| async move {
                handler.uni_channel_created(&mut *eng, info)
            })
            .await?;
        let secret = Secret::from(psk.raw_secret_bytes());
        Ok(AqcUniPsk {
            identity: psk.identity().into(),
            secret: if self.device_id == info.send_id {
                Directed::Send(secret)
            } else {
                Directed::Recv(secret)
            },
        })
    }

    pub(crate) async fn uni_channel_received(
        &self,
        info: &UniChannelReceived<'_>,
    ) -> Result<AqcUniPsk> {
        let psk = self
            .while_locked(|mut handler, mut eng| async move {
                handler.uni_channel_received(&mut *eng, info)
            })
            .await?;
        let secret = Secret::from(psk.raw_secret_bytes());
        Ok(AqcUniPsk {
            identity: psk.identity().into(),
            secret: if self.device_id == info.send_id {
                Directed::Send(secret)
            } else {
                Directed::Recv(secret)
            },
        })
    }
}

impl<E, KS> fmt::Debug for Aqc<E, KS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aqc")
            .field("peers", &self.peers)
            .finish_non_exhaustive()
    }
}
