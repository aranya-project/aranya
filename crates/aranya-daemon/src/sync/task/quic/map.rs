use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use s2n_quic::{
    application::Error as AppError,
    connection::{Handle, StreamAcceptor},
    Connection,
};
use tokio::sync::{self, mpsc, Mutex};

use crate::sync::task::quic::ConnectionKey;

pub(crate) type ConnectionUpdate = (ConnectionKey, StreamAcceptor);
type ConnectionMap = BTreeMap<ConnectionKey, Arc<Mutex<Handle>>>;

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
    ) -> (Option<Arc<Mutex<Handle>>>, Arc<Mutex<Handle>>) {
        let (handle, acceptor) = conn.split();

        let handle = Arc::new(Mutex::new(handle));
        let existing = self.deref_mut().insert(key, Arc::clone(&handle));
        self.tx.send((key, acceptor)).await.expect("channel closed");

        (existing, handle)
    }

    pub(super) async fn remove(&mut self, key: ConnectionKey) {
        if let Some(existing_conn) = self.deref_mut().remove(&key) {
            // TODO: Use appropriate error code
            existing_conn.lock().await.close(AppError::UNKNOWN);
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
    data: Mutex<BTreeMap<ConnectionKey, Arc<Mutex<Handle>>>>,
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
