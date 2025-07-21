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
use tokio::sync::{self, mpsc, Mutex, RwLock};

use crate::sync::task::quic::ConnectionKey;

pub(crate) enum Msg<T, U> {
    Insert((T, U)),
    Remove(T),
}

pub(crate) type Notification = Msg<ConnectionKey, StreamAcceptor>;
type ConnectionMap = BTreeMap<ConnectionKey, Arc<Mutex<Handle>>>;

pub(super) struct RwLockWriteGuard<'a, T: ?Sized> {
    tx: mpsc::Sender<Notification>,
    guard: sync::RwLockWriteGuard<'a, T>,
}

#[allow(clippy::expect_used, reason = "channel closed")]
impl RwLockWriteGuard<'_, ConnectionMap> {
    pub(super) async fn insert(
        &mut self,
        key: ConnectionKey,
        conn: Connection,
    ) -> (Option<Arc<Mutex<Handle>>>, Arc<Mutex<Handle>>) {
        let (handle, acceptor) = conn.split();

        let handle = Arc::new(Mutex::new(handle));
        let existing = self.deref_mut().insert(key, Arc::clone(&handle));
        self.tx
            .send(Msg::Insert((key, acceptor)))
            .await
            .expect("channel closed");

        (existing, handle)
    }

    pub(super) async fn remove(&mut self, key: ConnectionKey) {
        if let Some(existing_conn) = self.deref_mut().remove(&key) {
            self.tx
                .send(Msg::Remove(key))
                .await
                .expect("channel closed");

            // TODO: Use appropriate error code
            existing_conn.lock().await.close(AppError::UNKNOWN);
        }
    }
}

impl<'a, T> Deref for RwLockWriteGuard<'a, T> {
    type Target = sync::RwLockWriteGuard<'a, T>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

#[derive(Debug)]
pub(crate) struct SharedConnectionMap {
    data: RwLock<BTreeMap<ConnectionKey, Arc<Mutex<Handle>>>>,
    tx: mpsc::Sender<Notification>,
}

impl SharedConnectionMap {
    pub(crate) fn new() -> (Self, mpsc::Receiver<Notification>) {
        let (tx, rx) = mpsc::channel(10);

        (
            Self {
                data: RwLock::new(BTreeMap::new()),
                tx,
            },
            rx,
        )
    }

    #[inline]
    pub(super) async fn read(&self) -> sync::RwLockReadGuard<'_, ConnectionMap> {
        self.data.read().await
    }

    #[inline]
    pub(super) async fn write(&self) -> RwLockWriteGuard<'_, ConnectionMap> {
        let guard = self.data.write().await;
        RwLockWriteGuard {
            guard,
            tx: self.tx.clone(),
        }
    }
}
