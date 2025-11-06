//! Hello notification functionality for Aranya QUIC sync.
//!
//! This module handles subscription management and broadcasting of hello notifications
//! when graph heads change, allowing peers to stay synchronized.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use aranya_runtime::{Address, GraphId, PeerCache, Storage, StorageProvider, SyncHelloType};
use aranya_util::Addr;
use dashmap::DashMap;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::{
    sync::{
        manager::{ProtocolConfig, SyncHandle},
        PeerCacheMap, Result, SyncPeer,
    },
    Client,
};

/// Storage for sync hello subscriptions
#[derive(Debug, Clone)]
pub struct HelloSubscription {
    /// Delay between notifications when graph changes (rate limiting)
    graph_change_delay: Duration,
    /// Last notification time for delay management
    last_notified: Option<Instant>,
    /// Expiration time of the subscription
    expires_at: Instant,
    /// Token to cancel the scheduled sending task
    cancel_token: CancellationToken,
}

/// Service for managing hello notifications.
#[derive(Debug, Clone)]
pub struct HelloService {
    client: Client,
    caches: PeerCacheMap,
    server_addr: Addr,
    subscriptions: Arc<DashMap<SyncPeer, HelloSubscription>>,
    sync_handle: SyncHandle,
}

impl HelloService {
    /// Creates a new hello service.
    pub fn new(
        config: ProtocolConfig,
        subscriptions: Arc<DashMap<SyncPeer, HelloSubscription>>,
        sync_handle: SyncHandle,
    ) -> Self {
        Self {
            client: config.client,
            caches: config.caches,
            server_addr: config.server_addr,
            subscriptions,
            sync_handle,
        }
    }

    /// Notify all subscribers when a graph head changes.
    pub async fn notify_subscribers(&self, graph_id: GraphId, head: Address) -> Result<()> {
        let now = Instant::now();
        let subscribers = self.get_valid_subscribers(graph_id, now);

        trace!(
            ?graph_id,
            ?head,
            count = subscribers.len(),
            "notifying subscribers"
        );

        for subscriber_addr in subscribers {
            let peer = SyncPeer::new(subscriber_addr, graph_id);

            match self.notify_peer(peer, head).await {
                Ok(()) => {
                    self.subscriptions
                        .entry(peer)
                        .and_modify(|sub| sub.last_notified = Some(now));
                }
                Err(error) => {
                    warn!(%error, peer = %peer.addr, graph = %peer.graph_id, ?head, "failed to notify subscriber");
                }
            }
        }

        Ok(())
    }

    /// Handle an incoming message from a peer.
    pub async fn handle_message(&self, peer: SyncPeer, msg: SyncHelloType<Addr>) -> Result<()> {
        match msg {
            SyncHelloType::Subscribe {
                delay_milliseconds,
                duration_milliseconds,
                address,
            } => {
                let subscriber = SyncPeer::new(address, peer.graph_id);
                let delay = Duration::from_millis(delay_milliseconds);
                let duration = Duration::from_millis(duration_milliseconds);
                self.subscribe(subscriber, delay, duration).await
            }
            SyncHelloType::Unsubscribe { address } => {
                let subscriber = SyncPeer::new(address, peer.graph_id);
                self.unsubscribe(subscriber).await
            }
            SyncHelloType::Hello { head, address } => {
                let sender = SyncPeer::new(address, peer.graph_id);
                self.receive_notification(sender, head).await
            }
        }
    }

    /// Handle a subscribe request.
    async fn subscribe(&self, peer: SyncPeer, delay: Duration, duration: Duration) -> Result<()> {
        let expires_at = Instant::now() + duration;
        let cancel_token = CancellationToken::new();

        // We're registering a new subscription for an existing peer, so let's cancel the current task driving it.
        if let Some(old_sub) = self.subscriptions.get(&peer) {
            old_sub.cancel_token.cancel();
            debug!(peer = %peer.addr, graph = %peer.graph_id, "cancelled previous subscription");
        }

        let subscription = HelloSubscription {
            graph_change_delay: delay,
            last_notified: None,
            expires_at,
            cancel_token: cancel_token.clone(),
        };

        self.subscriptions.insert(peer, subscription);
        debug!(peer = %peer.addr, graph = %peer.graph_id, graph_change_delay = ?delay, ?expires_at, "created subscription");

        tokio::spawn(Self::periodic_notifier(
            peer,
            delay,
            expires_at,
            cancel_token,
            self.client.clone(),
            self.sync_handle.clone(),
        ));

        Ok(())
    }

    /// Handle an unsubscribe request.
    async fn unsubscribe(&self, peer: SyncPeer) -> Result<()> {
        match self.subscriptions.remove(&peer) {
            Some((_, subscription)) => {
                subscription.cancel_token.cancel();
                debug!(peer = %peer.addr, graph = %peer.graph_id, "removed subscription");
            }
            None => {
                debug!(peer = %peer.addr, graph = %peer.graph_id, "no subscription found to remove");
            }
        }

        Ok(())
    }

    /// Handle a notification from a peer about their new head.
    async fn receive_notification(&self, peer: SyncPeer, head: Address) -> Result<()> {
        debug!(peer = %peer.addr, graph = %peer.graph_id, ?head, "received notification");

        let needs_sync = {
            let mut aranya = self.client.aranya.lock().await;
            !aranya.command_exists(peer.graph_id, head)
        };

        if needs_sync {
            debug!(peer = %peer.addr, graph = %peer.graph_id, ?head, "triggering sync");

            if let Err(error) = self.sync_handle.trigger_sync(peer).await {
                warn!(%error, peer = %peer.addr, graph = %peer.graph_id, ?head, "failed to trigger sync");
            }
        }

        let mut aranya = self.client.aranya.lock().await;
        let mut cache = self.caches.entry(peer).or_insert_with(PeerCache::default);

        match aranya.update_heads(peer.graph_id, [head], &mut cache) {
            Ok(()) => {
                trace!(peer = %peer.addr, graph = %peer.graph_id, ?head, "updated peer cache");
            }
            Err(error) => {
                warn!(%error, peer = %peer.addr, graph = %peer.graph_id, ?head, "failed to update peer cache");
            }
        }

        Ok(())
    }

    /// Send a notification to a specific peer.
    async fn notify_peer(&self, peer: SyncPeer, head: Address) -> Result<()> {
        self.sync_handle
            .send_notification(peer, head)
            .await
            .context("failed to send notification via manager")?;

        trace!(peer = %peer.addr, graph = %peer.graph_id, ?head, "sent notification");

        Ok(())
    }

    /// Get valid subscribers for a graph (non-expired, not rate-limited).
    fn get_valid_subscribers(&self, graph_id: GraphId, now: Instant) -> Vec<Addr> {
        // NB: it's probably better to allocate normally than over-allocate using self.subscriptions.len().
        let mut subscribers = Vec::new();

        // Remove all expired subscriptions and collect valid addresses for the target graph.
        self.subscriptions.retain(|peer, subscription| {
            // Remove all expired subscriptions (includes other graph_ids).
            if now >= subscription.expires_at {
                debug!(address = ?peer.addr, graph_id = ?peer.graph_id, "removed expired subscription");
                return false;
            }

            if peer.graph_id == graph_id {
                if let Some(last) = subscription.last_notified {
                    // If our rate limit hasn't yet expired, retain it but don't return it yet.
                    if now - last < subscription.graph_change_delay {
                        return true;
                    }
                }
                subscribers.push(peer.addr);
            }

            true
        });

        subscribers
    }

    async fn periodic_notifier(
        peer: SyncPeer,
        schedule_delay: Duration,
        expires_at: Instant,
        cancel_token: CancellationToken,
        client: Client,
        sync_handle: SyncHandle,
    ) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(schedule_delay) => {
                    if Instant::now() >= expires_at {
                        debug!(peer = %peer.addr, graph = %peer.graph_id, "subscription expired, exiting notifier");
                        break;
                    }

                    let head = {
                        let mut aranya = client.aranya.lock().await;
                        let storage = match aranya.provider().get_storage(peer.graph_id) {
                            Ok(storage) => storage,
                            Err(error) => {
                                warn!(%error, peer = %peer.addr, graph = %peer.graph_id, "failed to get storage for hello sync");
                                continue;
                            }
                        };

                        match storage.get_head_address() {
                            Ok(addr) => addr,
                            Err(error) => {
                                warn!(%error, peer = %peer.addr, graph = %peer.graph_id, "failed to get head for hello sync");
                                continue;
                            }
                        }
                    };

                    match sync_handle.send_notification(peer, head).await {
                        Ok(()) => trace!(peer = %peer.addr, graph = %peer.graph_id, ?head, "sent periodic notification"),
                        Err(error) => warn!(%error, peer = %peer.addr, graph = %peer.graph_id, "failed to send periodic notification"),
                    }
                }
                _ = cancel_token.cancelled() => {
                    debug!(peer = %peer.addr, graph = %peer.graph_id, "subscription cancelled, exiting notifier");
                    break;
                }
            }
        }
    }
}
