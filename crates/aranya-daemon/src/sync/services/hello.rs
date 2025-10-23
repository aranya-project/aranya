//! Hello notification functionality for Aranya QUIC sync.
//!
//! This module handles subscription management and broadcasting of hello notifications
//! when graph heads change, allowing peers to stay synchronized.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use aranya_runtime::{Address, GraphId, SyncHelloType, SyncType};
use tokio::{io::AsyncReadExt, sync::Mutex};
use tracing::{debug, instrument, trace, warn};

use crate::{
    sync::{
        manager::{SyncHandle, SyncManager},
        transport::quic::{QuicError, QuicTransport},
        Result as SyncResult,
    },
    Addr,
};

/// A hello subscription from a peer.
#[derive(Debug, Clone)]
pub struct HelloSubscription {
    /// Delay between notifications to this subscriber (milliseconds)
    pub(crate) delay_milliseconds: u64,
    /// Last time we sent a notification
    pub(crate) last_notified: Option<Instant>,
    /// When this subscription expires
    pub(crate) expires_at: Instant,
}

/// Maps from (team_id, subscriber_address) to subscription details
pub type HelloSubscriptions = HashMap<(GraphId, Addr), HelloSubscription>;

/// Hello-related information combining subscriptions and sync peers.
#[derive(Debug, Clone)]
pub struct HelloInfo {
    /// Storage for sync hello subscriptions
    pub subscriptions: Arc<Mutex<HelloSubscriptions>>,
    /// Interface to trigger sync operations
    pub sync_peers: SyncHandle,
}

impl SyncManager<QuicTransport> {
    /// Broadcast hello notifications to all subscribers of a graph.
    #[instrument(skip_all)]
    pub async fn broadcast_hello_notifications(
        &mut self,
        graph_id: GraphId,
        head: Address,
    ) -> SyncResult<()> {
        // Get all subscribers for this graph
        let subscribers = {
            let subscriptions = self.state.hello_subscriptions().lock().await;

            let filtered: Vec<_> = subscriptions
                .iter()
                .filter(|((sub_graph_id, _), _)| *sub_graph_id == graph_id)
                .map(|((_, addr), subscription)| (*addr, subscription.clone()))
                .collect();

            filtered
        };

        let now = Instant::now();

        // Send hello notification to each subscriber
        for (subscriber_addr, subscription) in subscribers.iter() {
            // Check if subscription has expired
            if now >= subscription.expires_at {
                // Remove expired subscription
                let mut subscriptions = self.state.hello_subscriptions().lock().await;
                subscriptions.remove(&(graph_id, *subscriber_addr));
                debug!(?subscriber_addr, ?graph_id, "Removed expired subscription");
                continue;
            }

            // Check if enough time has passed since last notification
            if let Some(last_notified) = subscription.last_notified {
                let delay = Duration::from_millis(subscription.delay_milliseconds);
                if now - last_notified < delay {
                    continue;
                }
            }

            // Send the notification
            match self
                .send_hello_notification_to_subscriber(subscriber_addr, graph_id, head)
                .await
            {
                Ok(()) => {
                    // Update the last notified time
                    let mut subscriptions = self.state.hello_subscriptions().lock().await;
                    if let Some(sub) = subscriptions.get_mut(&(graph_id, *subscriber_addr)) {
                        sub.last_notified = Some(now);
                    } else {
                        warn!(
                            ?subscriber_addr,
                            ?graph_id,
                            "Failed to find subscription to update last_notified"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        ?subscriber_addr,
                        ?head,
                        "Failed to send hello notification"
                    );
                }
            }
        }

        trace!(
            ?graph_id,
            ?head,
            subscriber_count = subscribers.len(),
            "Completed broadcast_hello_notifications"
        );
        Ok(())
    }

    /// Sends a hello message to a peer and waits for a response.
    ///
    /// This is a helper method that handles the common logic for sending hello messages,
    /// including serialization, connection management, and response handling.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to send the message to
    /// * `id` - The graph ID for the team/graph
    /// * `sync_type` - The hello message to send
    /// * `operation_name` - Name of the operation for logging
    ///
    /// # Returns
    /// * `Ok(())` if the message was sent successfully
    /// * `Err(SyncError)` if there was an error
    #[instrument(skip_all)]
    async fn send_hello_request(
        &mut self,
        peer: &Addr,
        id: GraphId,
        sync_type: SyncType<Addr>,
        operation_name: &str,
    ) -> SyncResult<()> {
        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let stream = self.connect(peer, id).await?;
        let (mut recv, mut send) = stream.split();

        // Send the message
        send.send(bytes::Bytes::from(data))
            .await
            .map_err(QuicError::from)?;
        send.close().await.map_err(QuicError::from)?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .with_context(|| format!("failed to read hello {} response", operation_name))?;
        assert!(!response_buf.is_empty());
        Ok(())
    }

    /// Sends a subscribe request to a peer for hello notifications.
    ///
    /// This method sends a [`SyncHelloType::Subscribe`] message to the specified peer,
    /// requesting to be notified when the peer's graph head changes. The peer will
    /// send hello notifications with the specified delay between them.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to send the subscribe request to
    /// * `id` - The graph ID for the team/graph to subscribe to
    /// * `delay_milliseconds` - Delay in milliseconds between notifications (0 = immediate)
    /// * `subscriber_server_addr` - The address where this subscriber's QUIC sync server is listening
    ///
    /// # Returns
    /// * `Ok(())` if the subscribe request was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub async fn send_sync_hello_subscribe_request(
        &mut self,
        peer: &Addr,
        id: GraphId,
        delay: Duration,
        duration: Duration,
        subscriber_server_addr: Addr,
    ) -> SyncResult<()> {
        // Create the subscribe message
        let delay_milliseconds = delay.as_millis() as u64;
        let duration_milliseconds = duration.as_millis() as u64;
        let hello_msg = SyncHelloType::Subscribe {
            delay_milliseconds,
            duration_milliseconds,
            address: subscriber_server_addr,
        };
        let sync_type: SyncType<Addr> = SyncType::Hello(hello_msg);

        self.send_hello_request(peer, id, sync_type, "subscribe")
            .await
    }

    /// Sends an unsubscribe request to a peer to stop hello notifications.
    ///
    /// This method sends a `SyncHelloType::Unsubscribe` message to the specified peer,
    /// requesting to stop receiving hello notifications when the peer's graph head changes.
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
    pub async fn send_hello_unsubscribe_request(
        &mut self,
        peer: &Addr,
        id: GraphId,
        subscriber_server_addr: Addr,
    ) -> SyncResult<()> {
        debug!("client sending unsubscribe request to QUIC sync server");

        // Create the unsubscribe message
        let sync_type: SyncType<Addr> = SyncType::Hello(SyncHelloType::Unsubscribe {
            address: subscriber_server_addr,
        });

        self.send_hello_request(peer, id, sync_type, "unsubscribe")
            .await
    }

    /// Sends a hello notification to a specific subscriber.
    ///
    /// This method sends a `SyncHelloType::Hello` message to the specified subscriber,
    /// notifying them that the graph head has changed. Uses the existing connection
    /// infrastructure to efficiently reuse connections.
    ///
    /// # Arguments
    /// * `peer` - The network address of the subscriber to send the notification to
    /// * `id` - The graph ID for the team/graph
    /// * `head` - The new head address to include in the notification
    ///
    /// # Returns
    /// * `Ok(())` if the notification was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub async fn send_hello_notification_to_subscriber(
        &mut self,
        peer: &Addr,
        id: GraphId,
        head: Address,
    ) -> SyncResult<()> {
        // Set the team for this graph
        let team_id = id.into_id().into();
        self.state.store().set_team(team_id);

        // Create the hello message
        let hello_msg = SyncHelloType::Hello {
            head,
            address: self.server_addr,
        };
        let sync_type: SyncType<Addr> = SyncType::Hello(hello_msg);

        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        let stream = self.connect(peer, id).await.map_err(|e| {
            warn!(
                error = %e,
                ?peer,
                ?id,
                "Failed to connect to peer"
            );
            e
        })?;
        let (mut recv, mut send) = stream.split();

        send.send(bytes::Bytes::from(data)).await.map_err(|e| {
            warn!(
                error = %e,
                ?peer,
                "Failed to send hello message"
            );
            QuicError::from(e)
        })?;

        send.close().await.map_err(|e| {
            warn!(
                error = %e,
                ?peer,
                "Failed to close send stream"
            );
            QuicError::from(e)
        })?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read hello notification response")?;
        debug!(
            response_len = response_buf.len(),
            "received hello notification response"
        );

        Ok(())
    }
}
