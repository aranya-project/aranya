use std::{iter::Cycle, sync::Arc};

use anyhow::{Context, Result};
use runtime::storage::GraphId;
use tracing::{error, info, instrument, warn};

use crate::{
    addr::Addr,
    daemon::{Client, EF},
    vm_policy::VecSink,
};

/// Syncs with each peer in order.
pub struct Syncer<I> {
    client: Arc<Client>,
    peers: Cycle<I>,
    graph_id: GraphId,
}

impl<I> Syncer<I>
where
    I: Clone + Iterator,
{
    /// Creates a new `Syncer`.
    pub fn new<V>(client: Arc<Client>, graph_id: GraphId, peers: V) -> Self
    where
        V: IntoIterator<IntoIter = I>,
    {
        Self {
            client,
            graph_id,
            peers: peers.into_iter().cycle(),
        }
    }

    // TODO: update peers.
}

impl<I> Syncer<I>
where
    I: Clone + Iterator<Item = Addr>,
{
    /// Syncs with the next peer in the list.
    #[instrument(skip_all)]
    pub async fn next(&mut self) -> Result<()> {
        let Some(peer) = self.peers.next() else {
            // `Cycle` only returns `None` if the underlying
            // iterator is empty.
            warn!("no peers to debug with");
            return Ok(());
        };
        self.sync(&self.graph_id.clone(), &peer).await
    }

    #[instrument(skip_all, fields(%peer, graph_id = %id))]
    async fn sync(&mut self, id: &GraphId, peer: &Addr) -> Result<()> {
        info!("syncing with peer");

        let effects: Vec<EF> = {
            let mut sink = VecSink::new();
            self.client
                .sync_peer(id, &mut sink, peer)
                .await
                .inspect_err(|err| error!(?err, ?peer, "unable to sync with peer"))
                .context("unable to sync with peer")?;
            sink.collect()?
        };
        info!(num = effects.len(), "completed sync");
        Ok(())
    }
}
