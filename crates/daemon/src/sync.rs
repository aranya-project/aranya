use std::{collections::HashSet, iter::Cycle, sync::Arc, vec::IntoIter};

use anyhow::{Context, Result};
use runtime::storage::GraphId;
use tracing::{error, info, instrument, warn};

use crate::{
    addr::Addr,
    daemon::{Client, EF},
    vm_policy::VecSink,
};

/// Syncs with each peer in order.
pub struct Syncer {
    client: Arc<Client>,
    peers: HashSet<Addr>,
    graph_id: Option<GraphId>,
    cycle: Cycle<IntoIter<Addr>>,
}

impl Syncer {
    /// Creates a new `Syncer`.
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            graph_id: None,
            peers: HashSet::new(),
            cycle: Vec::new().into_iter().cycle(),
        }
    }

    /// Set the graph id.
    pub fn set_graph_id(&mut self, graph_id: GraphId) -> Result<()> {
        self.graph_id = Some(graph_id);
        Ok(())
    }

    /// Add peer to sync rotation.
    pub fn add_peer(&mut self, peer: Addr) -> Result<()> {
        if self.peers.insert(peer) {
            self.update_cycle();
        }
        Ok(())
    }

    /// Remove peer from sync rotation.
    pub fn remove_peer(&mut self, peer: Addr) -> Result<()> {
        if self.peers.remove(&peer) {
            self.update_cycle();
        }
        Ok(())
    }

    /// Update the peer cycle.
    fn update_cycle(&mut self) {
        // TODO: better way to convert HashSet to cycle.
        let mut v = Vec::new();
        for p in &self.peers {
            v.push(*p);
        }
        self.cycle = v.into_iter().cycle();
    }
}

impl Syncer {
    /// Syncs with the next peer in the list.
    #[instrument(skip_all)]
    pub async fn next(&mut self) -> Result<()> {
        if let Some(graph_id) = self.graph_id {
            let Some(peer) = self.cycle.next() else {
                // `Cycle` only returns `None` if the underlying
                // iterator is empty.
                warn!("no peers to debug with");
                return Ok(());
            };
            self.sync(&graph_id.clone(), &peer).await?
        }
        Ok(())
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
