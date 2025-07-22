//! This modules contains a map for storing persistent QUIC connections between pairs of sync peers.
//! Once a connection has been opened, it is shared between the QUIC syncer client and server.

use std::{
    collections::{btree_map::Entry, BTreeMap},
    ops::{Deref, DerefMut},
};

use s2n_quic::{
    application::Error as AppError,
    connection::{Handle, StreamAcceptor},
    Connection,
};
use tokio::sync::{self, mpsc, Mutex};

use crate::sync::task::quic::ConnectionKey;

/// A [`ConnectionKey`] and [`StreamAcceptor`] pair that is sent over a channel
/// when a new connection is inserted.
pub(crate) type ConnectionUpdate = (ConnectionKey, StreamAcceptor);
type ConnectionMap = BTreeMap<ConnectionKey, Handle>;

pub(super) struct MutexGuard<'a, T: ?Sized> {
    tx: mpsc::Sender<ConnectionUpdate>,
    guard: sync::MutexGuard<'a, T>,
}

#[allow(clippy::expect_used, reason = "channel closed")]
impl MutexGuard<'_, ConnectionMap> {
    pub(super) async fn insert(
        &mut self,
        key: ConnectionKey,
        conn: Connection,
    ) -> (&mut Handle, bool) {
        let (new_handle, acceptor) = conn.split();

        let (handle, inserted) = match self.guard.entry(key) {
            Entry::Occupied(mut occupied_handle_entry) => {
                if occupied_handle_entry.get_mut().ping().is_ok() {
                    // TODO: Use appropriate error code
                    new_handle.close(AppError::UNKNOWN);

                    (occupied_handle_entry.into_mut(), false)
                } else {
                    let _ = occupied_handle_entry.insert(new_handle);
                    (occupied_handle_entry.into_mut(), true)
                }
            }
            Entry::Vacant(entry) => (entry.insert(new_handle), true),
        };

        if inserted {
            self.tx.send((key, acceptor)).await.expect("channel closed");
        }

        (handle, inserted)
    }

    pub(super) async fn remove(&mut self, key: ConnectionKey) {
        if let Some(existing_conn) = self.guard.remove(&key) {
            // TODO: Use appropriate error code
            existing_conn.close(AppError::UNKNOWN);
        }
    }
}

impl<'a, T> Deref for MutexGuard<'a, T> {
    type Target = sync::MutexGuard<'a, T>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

#[derive(Debug)]
pub(crate) struct SharedConnectionMap {
    data: Mutex<BTreeMap<ConnectionKey, Handle>>,
    tx: mpsc::Sender<ConnectionUpdate>,
}

impl SharedConnectionMap {
    pub(crate) fn new() -> (Self, mpsc::Receiver<ConnectionUpdate>) {
        let (tx, rx) = mpsc::channel(10);

        (
            Self {
                data: Mutex::new(BTreeMap::new()),
                tx,
            },
            rx,
        )
    }

    #[inline]
    pub(super) async fn lock(&self) -> MutexGuard<'_, ConnectionMap> {
        let guard = self.data.lock().await;
        MutexGuard {
            guard,
            tx: self.tx.clone(),
        }
    }
}
