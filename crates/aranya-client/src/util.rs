use aranya_id::{Id, IdTag};
use std::time::{Duration, Instant};
use tarpc::context;
use tarpc::trace::TraceId as TarpcTraceId;
use tarpc::trace::{Context as TraceContext, SamplingDecision, SpanId};

use crate::trace::TraceId;

/// IPC timeout of 1 year (365 days).
/// A large value helps resolve IPC calls timing out when there are long-running
/// operations happening in the daemon.
const IPC_TIMEOUT: Duration = Duration::from_secs(365 * 24 * 60 * 60);

pub(crate) trait ApiId<A> {}
pub(crate) trait ApiConv<A> {
    fn into_api(self) -> A;
    fn from_api(val: A) -> Self;
}

impl<TTag, ATag> ApiConv<Id<ATag>> for Id<TTag>
where
    TTag: IdTag,
    ATag: IdTag,
    Id<TTag>: ApiId<Id<ATag>>,
{
    fn into_api(self) -> Id<ATag> {
        Id::transmute(self)
    }

    fn from_api(val: Id<ATag>) -> Self {
        Id::transmute(val)
    }
}

/// Implement iterator traits for newtype wrappers
/// over `slice::Iter`.
macro_rules! impl_slice_iter_wrapper {
    ($wrapper:ident <$lifetime:lifetime> for $item:ty) => {
        impl<$lifetime> Iterator for $wrapper<$lifetime> {
            type Item = &$lifetime $item;

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                self.0.next()
            }

            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.0.size_hint()
            }

            #[inline]
            fn count(self) -> usize {
                self.0.count()
            }

            #[inline]
            fn nth(&mut self, n: usize) -> Option<Self::Item> {
                self.0.nth(n)
            }

            #[inline]
            fn last(self) -> Option<Self::Item> {
                self.0.last()
            }

            #[inline]
            fn fold<B, F>(self, init: B, f: F) -> B
            where
                F: FnMut(B, Self::Item) -> B,
            {
                self.0.fold(init, f)
            }

            #[inline]
            fn for_each<F>(self, f: F)
            where
                F: FnMut(Self::Item),
            {
                self.0.for_each(f)
            }

            #[inline]
            fn all<F>(&mut self, f: F) -> bool
            where
                F: FnMut(Self::Item) -> bool,
            {
                self.0.all(f)
            }

            #[inline]
            fn any<F>(&mut self, f: F) -> bool
            where
                F: FnMut(Self::Item) -> bool,
            {
                self.0.any(f)
            }

            #[inline]
            fn find<P>(&mut self, predicate: P) -> Option<Self::Item>
            where
                P: FnMut(&Self::Item) -> bool,
            {
                self.0.find(predicate)
            }

            #[inline]
            fn position<P>(&mut self, predicate: P) -> Option<usize>
            where
                P: FnMut(Self::Item) -> bool,
            {
                self.0.position(predicate)
            }

            #[inline]
            fn rposition<P>(&mut self, predicate: P) -> Option<usize>
            where
                P: FnMut(Self::Item) -> bool,
            {
                self.0.rposition(predicate)
            }
        }

        impl<$lifetime> DoubleEndedIterator for $wrapper<$lifetime> {
            #[inline]
            fn next_back(&mut self) -> Option<Self::Item> {
                self.0.next_back()
            }

            #[inline]
            fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
                self.0.nth_back(n)
            }
        }

        impl<$lifetime> ExactSizeIterator for $wrapper<$lifetime> {
            #[inline]
            fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl<$lifetime> ::core::iter::FusedIterator for $wrapper<$lifetime> {}
    };
}
pub(crate) use impl_slice_iter_wrapper;

/// Implement iterator traits for newtype wrappers over
/// `vec::IntoIter`.
macro_rules! impl_vec_into_iter_wrapper {
    ($wrapper:ident for $item:ty) => {
        impl Iterator for $wrapper {
            type Item = $item;

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                self.0.next()
            }

            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.0.size_hint()
            }

            #[inline]
            fn count(self) -> usize {
                self.0.count()
            }

            #[inline]
            fn last(self) -> Option<Self::Item> {
                self.0.last()
            }

            #[inline]
            fn fold<B, F>(self, init: B, f: F) -> B
            where
                F: FnMut(B, Self::Item) -> B,
            {
                self.0.fold(init, f)
            }
        }

        impl DoubleEndedIterator for $wrapper {
            #[inline]
            fn next_back(&mut self) -> Option<Self::Item> {
                self.0.next_back()
            }
        }

        impl ExactSizeIterator for $wrapper {
            #[inline]
            fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl ::core::iter::FusedIterator for $wrapper {}
    };
}
pub(crate) use impl_vec_into_iter_wrapper;

/// Creates a new tarpc context with trace metadata.
///
/// This function generates a fresh context for each RPC call, including
/// a unique trace ID that will be propagated through the daemon and
/// correlated in all logs.
///
/// The trace ID is generated client-side and logged, enabling end-to-end
/// request tracking across client and daemon components.
///
/// # Example
///
/// ```rust,ignore
/// use aranya_client::util::rpc_context;
/// let ctx = rpc_context();
/// client.create_team(ctx, cfg).await?;
/// ```
///
/// # How It Works
///
/// - Gets current tarpc context
/// - Generates unique trace_id
/// - Logs the trace ID for client-side tracing
/// - Returns context for use in RPC calls
pub(crate) fn rpc_context() -> context::Context {
    let mut ctx = context::current();
    ctx.deadline = Instant::now()
        .checked_add(IPC_TIMEOUT)
        .expect("IPC_TIMEOUT should not overflow");
    let mut rng = rand::thread_rng();
    ctx.trace_context = TraceContext {
        trace_id: TarpcTraceId::random(&mut rng),
        span_id: SpanId::random(&mut rng),
        sampling_decision: SamplingDecision::Sampled,
    };
    let trace_id = TraceId::new();
    tracing::debug!(%trace_id, "generated RPC context with tarpc trace");
    ctx
}
