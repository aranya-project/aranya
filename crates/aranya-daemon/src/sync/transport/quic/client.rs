use std::{collections::HashMap, sync::Arc};

use aranya_runtime::{PolicyStore, StorageProvider};
use buggy::BugExt as _;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::time::DelayQueue;

use super::{Error, PskStore, QuicTransport, SharedConnectionMap};
#[cfg(feature = "preview")]
use crate::sync::HelloSubscriptions;
use crate::{
    aranya::Client,
    sync::{Addr, Callback, GraphId, SyncManager},
};

impl<PS, SP, EF> SyncManager<QuicTransport, PS, SP, EF>
where
    PS: PolicyStore,
    SP: StorageProvider,
{
    /// Creates a new [`SyncManager`].
    pub(crate) fn new(
        client: Client<PS, SP>,
        send_effects: mpsc::Sender<(GraphId, Vec<EF>)>,
        psk_store: Arc<PskStore>,
        (server_addr, client_addr): (Addr, Addr),
        recv: mpsc::Receiver<Callback>,
        conns: SharedConnectionMap,
    ) -> Result<Self, Error> {
        let return_address =
            Bytes::from(postcard::to_allocvec(&server_addr).assume("can serialize addr")?);
        let transport = QuicTransport::new(client_addr, conns, psk_store, return_address.clone())?;

        Ok(Self {
            client,
            peers: HashMap::new(),
            recv,
            queue: DelayQueue::new(),
            send_effects,
            transport,
            #[cfg(feature = "preview")]
            hello_subscriptions: HelloSubscriptions::new(),
        })
    }
}
