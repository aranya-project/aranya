use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// All [`Notifier`]s were dropped before notifying.
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[error("ready notifiers dropped before notifying")]
pub struct ReadyError;

/// Waits for `n` tasks to be ready.
#[derive(Debug)]
pub struct Waiter {
    rx: tokio::sync::mpsc::Receiver<()>,
    notifier: Notifier,
}

impl Waiter {
    /// Create a waiter that will wait for `count` ready notifications.
    pub fn new(count: usize) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        Self {
            rx,
            notifier: Notifier {
                count: Arc::new(AtomicUsize::new(count)),
                tx,
            },
        }
    }

    /// Get a notifier associated with this waiter.
    pub fn notifier(&self) -> Notifier {
        self.notifier.clone()
    }

    /// Wait for `count` ready notifications.
    pub async fn wait(mut self) -> Result<(), ReadyError> {
        drop(self.notifier);
        self.rx.recv().await.ok_or(ReadyError)
    }
}

/// Notifies that a task is ready.
#[derive(Clone, Debug)]
pub struct Notifier {
    count: Arc<AtomicUsize>,
    tx: tokio::sync::mpsc::Sender<()>,
}

impl Notifier {
    /// Notifies that one task is ready.
    ///
    /// After `count` calls, [`Waiter::wait`] will resolve.
    pub fn notify(self) {
        if self.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tx.try_send(()).ok();
        }
    }
}
