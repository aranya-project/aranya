use core::{any::Any, future::Future, panic::AssertUnwindSafe};
use std::panic::resume_unwind;

use futures_util::FutureExt as _;
use tokio::sync::mpsc;
use tokio_util::task::TaskTracker;

// TODO(jdygert): Abort all tasks on drop?

/// Creates a scope for spawning scoped async tasks for structured concurrency.
///
/// The given function will be provided a [`Scope`] through which tasks can be
/// [`spawned`][Scope::spawn]. The resulting future will pend until all tasks have finished.
/// The tracked tasks can free their memory as soon as they finish, making this well suited for
/// spawning many short lived tasks over time.
///
/// Unlike [`std::thread::scope`], this function does not let you spawn tasks which borrow from the
/// local scope, since there is no safe way to do so.
///
/// # Panics
///
/// If any of the spawned tasks panic, this future will panic.
///
/// # Example
///
/// ```no_run
/// # async fn test() {
/// # use core::time::Duration;
/// # use tokio::time::sleep;
/// use aranya_util::task::scope;
/// // prints "Hello, world!" after 1s and resolves after 10s.
/// scope(async |s| {
///     s.spawn(async {
///         sleep(Duration::from_secs(10)).await;
///     });
///
///     let msg = String::from("Hello, world!");
///     s.spawn(async move {
///         sleep(Duration::from_secs(1)).await;
///         println!("{msg}");
///     });
/// }).await;
/// # }
/// ```
pub async fn scope<F>(f: F)
where
    F: for<'a> AsyncFnOnce(&'a mut Scope),
{
    #![allow(clippy::disallowed_macros, reason = "unreachable in select")]

    let (mut scope, mut rx) = Scope::new();
    let run = async {
        f(&mut scope).await;
        scope.tracker.close();
        scope.tracker.wait().await;
    };
    tokio::select! {
        Some(err) = rx.recv() => {
            resume_unwind(err);
        }
        () = run => {
            drop(scope);
            if let Some(err) = rx.recv().await {
                resume_unwind(err);
            }
        }
    }
}

type Panic = Box<dyn Any + Send>;

pub struct Scope {
    tracker: TaskTracker,
    tx: mpsc::Sender<Panic>,
}
impl Scope {
    fn new() -> (Self, mpsc::Receiver<Panic>) {
        let (tx, rx) = mpsc::channel(1);
        (
            Self {
                tracker: TaskTracker::new(),
                tx,
            },
            rx,
        )
    }

    /// Spawns a future as a task.
    ///
    /// The future must be `Send + 'static`.
    pub fn spawn<Fut>(&mut self, fut: Fut)
    where
        Fut: Future<Output = ()> + Send + 'static,
    {
        let tx = self.tx.clone();
        self.tracker.spawn(async move {
            // Note: Tokio's join error gives you the panic payload anyways, so using
            // `AssertUnwindSafe` here isn't any less unwind-safe than that.
            // (`UnwindSafe` is more like a lint anyways.)
            if let Err(err) = AssertUnwindSafe(fut).catch_unwind().await {
                _ = tx.try_send(err);
            }
        });
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::panic)]

    use std::{
        future::pending,
        sync::atomic::{AtomicU32, Ordering},
        time::Duration,
    };

    use tokio::time::sleep;
    use tokio_util::time::FutureExt as _;

    use super::scope;

    #[tokio::test]
    async fn test_scope_usage() {
        const ITERATIONS: u32 = 1000;
        const DELAY: Duration = Duration::from_millis(100);
        const TIMEOUT: Duration = Duration::from_secs(5);

        static COUNTER: AtomicU32 = AtomicU32::new(0);

        // This ensures that the task cannot be run sequentially within the timeout.
        assert!(ITERATIONS * DELAY > TIMEOUT);

        scope(async |s| {
            for _ in 0..ITERATIONS {
                s.spawn(async {
                    sleep(DELAY).await;
                    COUNTER.fetch_add(1, Ordering::AcqRel);
                });
            }
        })
        .timeout(TIMEOUT)
        .await
        .unwrap();
        assert_eq!(COUNTER.load(Ordering::Acquire), ITERATIONS);
    }

    #[tokio::test]
    #[should_panic(expected = "panic while spawning")]
    async fn test_panic_while_spawning() {
        scope(async |s| {
            s.spawn(pending());
            s.spawn(async move {
                panic!("panic while spawning");
            });
            s.spawn(pending());
            pending::<()>().await;
        })
        .timeout(Duration::from_secs(1))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "panic after spawning")]
    async fn test_panic_after_spawning() {
        scope(async |s| {
            s.spawn(pending());
            s.spawn({
                async {
                    sleep(Duration::from_millis(100)).await;
                    panic!("panic after spawning");
                }
            });
            s.spawn(pending());
        })
        .timeout(Duration::from_secs(1))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "panic in scope")]
    async fn test_panic_in_scope() {
        scope(async |s| {
            s.spawn(pending());
            panic!("panic in scope")
        })
        .timeout(Duration::from_secs(1))
        .await
        .unwrap();
    }
}
