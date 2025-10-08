//! Push notification functionality for Aranya QUIC sync.
//!
//! This module handles subscription management and broadcasting of push notifications
//! when new commands are available, allowing peers to stay synchronized.

use core::net::SocketAddr;
use std::{collections::HashMap, sync::Arc, time::Instant};

use anyhow::Context;
use aranya_crypto::{Csprng, Rng};
use aranya_runtime::{
    Address, GraphId, SyncRequestMessage, SyncResponder, SyncResponseMessage, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::Addr;
use heapless;
use tokio::{io::AsyncReadExt, sync::Mutex};
use tracing::{debug, instrument, warn};

use crate::sync::{
    task::{
        quic::{Error, State},
        PeerCacheKey, SyncPeers, Syncer,
    },
    Result as SyncResult,
};

/// Storage for sync push subscriptions
#[derive(Debug, Clone)]
pub struct PushSubscription {
    /// Close time for the subscription
    pub close_time: Instant,
    /// Maximum number of bytes that can be sent
    pub remaining_bytes: u64,
}

/// Type alias for push subscription storage
/// Maps from (team_id, subscriber_address) to subscription details
pub type PushSubscriptions = HashMap<(GraphId, SocketAddr), PushSubscription>;

/// Push-related information combining subscriptions and sync peers.
#[derive(Debug, Clone)]
pub struct PushInfo {
    /// Storage for sync push subscriptions
    pub subscriptions: Arc<Mutex<PushSubscriptions>>,
    /// Interface to trigger sync operations
    pub sync_peers: SyncPeers,
}

/// Broadcast push notifications to all subscribers of a graph.
#[instrument(skip_all)]
pub async fn broadcast_push_notifications(
    syncer: &mut Syncer<State>,
    graph_id: GraphId,
) -> SyncResult<()> {
    // Get all subscribers for this graph
    let subscribers = {
        let subscriptions = syncer.state.push_subscriptions().lock().await;
        let total_subs = subscriptions.len();

        let filtered: Vec<_> = subscriptions
            .iter()
            .filter(|((sub_graph_id, _), _)| *sub_graph_id == graph_id)
            .map(|((_, addr), subscription)| (*addr, subscription.clone()))
            .collect();

        tracing::info!(
            ?graph_id,
            total_subscriptions = total_subs,
            filtered_subscribers = filtered.len(),
            "📡 broadcast_push_notifications: Found subscribers for graph"
        );

        filtered
    };

    // Send push notification to each subscriber
    for (subscriber_addr, subscription) in subscribers.iter() {
        tracing::info!(
            ?subscriber_addr,
            ?graph_id,
            remaining_bytes = subscription.remaining_bytes,
            "📤 Processing subscriber for push notification"
        );
        
        // Check if subscription has expired
        if Instant::now() >= subscription.close_time || subscription.remaining_bytes == 0 {
            // Remove expired subscription
            let mut subscriptions = syncer.state.push_subscriptions().lock().await;
            subscriptions.remove(&(graph_id, *subscriber_addr));
            debug!(
                ?subscriber_addr,
                ?graph_id,
                "Removed expired push subscription"
            );
            continue;
        }

        // Generate a unique response for this subscriber based on their cache
        let peer_addr = Addr::from(*subscriber_addr);

        // Get the cached heads for this subscriber
        let peer_cache_key = PeerCacheKey::new(peer_addr, graph_id);
        let mut commands = heapless::Vec::new();
        {
            let mut caches = syncer.caches.lock().await;
            let response_cache = caches.entry(peer_cache_key).or_default();
            commands
                .extend_from_slice(response_cache.heads())
                .expect("failed to extend commands from cache heads");
        }

        // Generate a random session ID for this push
        let mut dst = [0u8; 16];
        Rng.fill_bytes(&mut dst);
        let session_id = u128::from_le_bytes(dst);

        // Create a SyncResponder to generate the push response
        let mut response_syncer = SyncResponder::new(syncer.server_addr);

        // Prepare the sync request with the subscriber's cached heads
        // Use the subscription's remaining bytes as the max_bytes limit
        let max_bytes = subscription.remaining_bytes.min(MAX_SYNC_MESSAGE_SIZE as u64);
        let sync_request = SyncRequestMessage::SyncRequest {
            session_id,
            storage_id: graph_id,
            max_bytes,
            commands,
        };

        // Receive the request and prepare to generate the response
        if let Err(e) = response_syncer.receive(sync_request) {
            warn!(
                error = %e,
                ?subscriber_addr,
                ?graph_id,
                "Failed to prepare sync response"
            );
            continue;
        }

        debug_assert!(response_syncer.ready());

        // Generate the push response based on what this subscriber is missing
        let mut target = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = {
            let mut aranya = syncer.client.aranya.lock().await;
            match response_syncer.push(&mut target, aranya.provider()) {
                Ok(len) => {
                    tracing::info!(
                        ?subscriber_addr,
                        ?graph_id,
                        len,
                        max_bytes,
                        "📦 response_syncer.push() returned"
                    );
                    len
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        ?subscriber_addr,
                        ?graph_id,
                        "Failed to generate push response"
                    );
                    continue;
                }
            }
        };

        // Only send if there's data to send
        if len == 0 {
            tracing::info!(
                ?subscriber_addr,
                ?graph_id,
                "⚠️ No new data to push to subscriber"
            );
            continue;
        }
        
        tracing::info!(
            ?subscriber_addr,
            ?graph_id,
            message_size = len,
            "📨 Sending push notification with data"
        );

        // Check if the message size exceeds remaining bytes
        if len as u64 > subscription.remaining_bytes {
            let mut subscriptions = syncer.state.push_subscriptions().lock().await;
            if let Some(sub) = subscriptions.get_mut(&(graph_id, *subscriber_addr)) {
                sub.remaining_bytes = 0;
            }
            debug!(
                ?subscriber_addr,
                ?graph_id,
                "Push message exceeds remaining bytes"
            );
            continue;
        }

        // Truncate the buffer to the actual data size
        target.truncate(len);

        // The push() method already creates a complete SyncType::Push message,
        // so we can send the bytes directly without deserializing and re-wrapping.
        // Send the notification directly
        match syncer
            .send_push_notification_raw(&peer_addr, graph_id, target)
            .await
        {
            Ok(bytes_sent) => {
                // Update the remaining bytes
                let mut subscriptions = syncer.state.push_subscriptions().lock().await;
                if let Some(sub) = subscriptions.get_mut(&(graph_id, *subscriber_addr)) {
                    if let Some(new_remaining) = sub.remaining_bytes.checked_sub(bytes_sent) {
                        sub.remaining_bytes = new_remaining;
                    } else {
                        sub.remaining_bytes = 0;
                    }
                    tracing::info!(
                        ?subscriber_addr,
                        ?graph_id,
                        bytes_sent,
                        remaining = sub.remaining_bytes,
                        "✅ Successfully sent push notification"
                    );
                } else {
                    tracing::warn!(
                        ?subscriber_addr,
                        ?graph_id,
                        "⚠️ Failed to find subscription to update remaining_bytes"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    ?subscriber_addr,
                    "❌ Failed to send push notification"
                );
            }
        }
    }

    Ok(())
}

impl Syncer<State> {
    /// Sends a subscribe request to a peer for push notifications.
    ///
    /// This method sends a `SyncType::Subscribe` message to the specified peer,
    /// requesting to receive push notifications when new commands are available.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to send the subscribe request to
    /// * `id` - The graph ID for the team/graph to subscribe to
    /// * `remain_open` - Number of seconds the subscription should remain open
    /// * `max_bytes` - Maximum number of bytes that can be sent
    /// * `commands` - Sample of the peer's graph heads
    /// * `subscriber_server_addr` - The address where this subscriber's QUIC sync server is listening
    ///
    /// # Returns
    /// * `Ok(())` if the subscribe request was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub async fn send_push_subscribe_request(
        &mut self,
        peer: &Addr,
        id: GraphId,
        remain_open: u64,
        max_bytes: u64,
        commands: Vec<Address>,
        subscriber_server_addr: Addr,
    ) -> SyncResult<()> {
        tracing::info!(
            ?peer,
            ?id,
            ?subscriber_server_addr,
            remain_open,
            max_bytes,
            "📮 Sending push subscribe request"
        );
        
        // Convert commands to the expected type
        let mut commands_heapless: heapless::Vec<Address, 100> = heapless::Vec::new();
        for addr in commands.into_iter().take(100) {
            if commands_heapless.push(addr).is_err() {
                break; // Shouldn't happen since we take only up to COMMAND_SAMPLE_MAX
            }
        }

        // Create the subscribe message
        let sync_type: aranya_runtime::SyncType<Addr> = aranya_runtime::SyncType::Subscribe {
            remain_open,
            max_bytes,
            commands: commands_heapless,
            storage_id: id,
            address: subscriber_server_addr,
        };

        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let stream = self.connect(peer, id).await?;
        let (mut recv, mut send) = stream.split();

        // Send the message
        send.send(bytes::Bytes::from(data))
            .await
            .map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read push subscribe response")?;
        tracing::info!(
            response_len = response_buf.len(),
            ?peer,
            ?id,
            "✅ Successfully sent push subscribe request and received response"
        );

        Ok(())
    }

    /// Sends an unsubscribe request to a peer to stop push notifications.
    ///
    /// This method sends a `SyncType::Unsubscribe` message to the specified peer,
    /// requesting to stop receiving push notifications.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to send the unsubscribe request to
    /// * `id` - The graph ID for the team/graph to unsubscribe from
    /// * `subscriber_server_addr` - The subscriber's server address to identify which subscription to remove
    ///
    /// # Returns
    /// * `Ok(())` if the unsubscribe request was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub async fn send_push_unsubscribe_request(
        &mut self,
        peer: &Addr,
        id: GraphId,
        subscriber_server_addr: Addr,
    ) -> SyncResult<()> {
        debug!("client sending push unsubscribe request to QUIC sync server");

        // Create the unsubscribe message
        let sync_type: aranya_runtime::SyncType<Addr> = aranya_runtime::SyncType::Unsubscribe {
            address: subscriber_server_addr,
        };

        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let stream = self.connect(peer, id).await?;
        let (mut recv, mut send) = stream.split();

        // Send the message
        send.send(bytes::Bytes::from(data))
            .await
            .map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read push unsubscribe response")?;
        debug!(
            response_len = response_buf.len(),
            "received push unsubscribe response"
        );

        debug!("sent push unsubscribe request");
        Ok(())
    }

    /// Sends a push notification to a specific subscriber using raw bytes.
    ///
    /// This method sends pre-serialized push notification bytes directly to the subscriber.
    /// The bytes should already be a complete SyncType::Push message.
    ///
    /// # Arguments
    /// * `peer` - The network address of the subscriber to send the notification to
    /// * `id` - The graph ID for the team/graph
    /// * `data` - The pre-serialized push notification message
    ///
    /// # Returns
    /// * `Ok(bytes_sent)` if the notification was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub async fn send_push_notification_raw(
        &mut self,
        peer: &Addr,
        id: GraphId,
        data: Vec<u8>,
    ) -> SyncResult<u64> {
        tracing::info!(
            ?peer,
            ?id,
            data_len = data.len(),
            "🔌 send_push_notification_raw: Sending raw push notification"
        );
        
        // Set the team for this graph
        let team_id = id.into_id().into();
        self.state.store().set_team(team_id);

        let bytes_to_send = data.len() as u64;

        tracing::info!(
            ?peer,
            ?id,
            bytes_to_send,
            "🔌 Attempting to connect to subscriber"
        );

        let stream = self.connect(peer, id).await.map_err(|e| {
            tracing::warn!(
                error = %e,
                ?peer,
                ?id,
                "❌ Failed to connect to peer"
            );
            e
        })?;
        
        tracing::info!(
            ?peer,
            ?id,
            "✅ Connected to subscriber, sending raw data"
        );
        let (mut recv, mut send) = stream.split();

        send.send(bytes::Bytes::from(data)).await.map_err(|e| {
            tracing::warn!(
                error = %e,
                ?peer,
                "❌ Failed to send push message"
            );
            Error::from(e)
        })?;
        
        tracing::info!(?peer, ?id, "📤 Data sent, closing send stream");

        send.close().await.map_err(|e| {
            tracing::warn!(
                error = %e,
                ?peer,
                "❌ Failed to close send stream"
            );
            Error::from(e)
        })?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read push notification response")?;
        tracing::info!(
            response_len = response_buf.len(),
            ?peer,
            ?id,
            "✅ Received push notification response, send complete"
        );

        Ok(bytes_to_send)
    }

    /// Sends a push notification to a specific subscriber.
    ///
    /// This method sends a `SyncType::Push` message to the specified subscriber,
    /// containing new commands that the subscriber doesn't have.
    ///
    /// # Arguments
    /// * `peer` - The network address of the subscriber to send the notification to
    /// * `id` - The graph ID for the team/graph
    /// * `response` - The sync response message containing new commands
    ///
    /// # Returns
    /// * `Ok(bytes_sent)` if the notification was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub async fn send_push_notification_to_subscriber(
        &mut self,
        peer: &Addr,
        id: GraphId,
        response: SyncResponseMessage,
    ) -> SyncResult<u64> {
        tracing::info!(
            ?peer,
            ?id,
            "🔌 send_push_notification_to_subscriber: Starting to send"
        );
        
        // Set the team for this graph
        let team_id = id.into_id().into();
        self.state.store().set_team(team_id);

        // Create the push message
        let sync_type: aranya_runtime::SyncType<Addr> = aranya_runtime::SyncType::Push {
            message: response,
            storage_id: id,
            address: self.server_addr,
        };

        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;
        let bytes_to_send = data.len() as u64;

        tracing::info!(
            ?peer,
            ?id,
            bytes_to_send,
            "🔌 Attempting to connect to subscriber"
        );

        let stream = self.connect(peer, id).await.map_err(|e| {
            tracing::warn!(
                error = %e,
                ?peer,
                ?id,
                "❌ Failed to connect to peer"
            );
            e
        })?;
        
        tracing::info!(
            ?peer,
            ?id,
            "✅ Connected to subscriber, sending data"
        );
        let (mut recv, mut send) = stream.split();

        send.send(bytes::Bytes::from(data)).await.map_err(|e| {
            tracing::warn!(
                error = %e,
                ?peer,
                "❌ Failed to send push message"
            );
            Error::from(e)
        })?;
        
        tracing::info!(?peer, ?id, "📤 Data sent, closing send stream");

        send.close().await.map_err(|e| {
            tracing::warn!(
                error = %e,
                ?peer,
                "❌ Failed to close send stream"
            );
            Error::from(e)
        })?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read push notification response")?;
        tracing::info!(
            response_len = response_buf.len(),
            ?peer,
            ?id,
            "✅ Received push notification response, send complete"
        );

        Ok(bytes_to_send)
    }
}
