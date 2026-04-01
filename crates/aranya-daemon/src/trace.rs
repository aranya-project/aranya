//! Distributed tracing context utilities.
//!
//! This module provides helpers for propagating RPC trace IDs
//! throughout the daemon's execution.

pub use tarpc::trace::TraceId;
use tracing::Span;

use crate::observability;

/// Extracts and records RPC trace context on the current span.
///
/// Also emits a receive log with trace ID for client/daemon correlation.
pub fn setup_trace_context(ctx: &tarpc::context::Context) {
    let trace_id = ctx.trace_context.trace_id;
    let rpc_deadline = ctx.deadline;
    Span::current().record("trace_id", tracing::field::display(trace_id));
    let otel_name = Span::current()
        .metadata()
        .map_or("rpc.unknown", |meta| meta.name());
    observability::log_rpc_receive_request(
        trace_id,
        rpc_deadline,
        observability::OTEL_KIND_SERVER,
        otel_name,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_setup_trace_context_from_tarpc_context() {
        let ctx = tarpc::context::current();
        setup_trace_context(&ctx);
        let trace_id = ctx.trace_context.trace_id;
        assert!(!trace_id.to_string().is_empty());
    }
}
