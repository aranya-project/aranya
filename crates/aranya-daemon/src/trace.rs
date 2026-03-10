//! Distributed tracing context utilities.
//!
//! This module provides helpers for propagating RPC trace IDs
//! throughout the daemon's execution.

pub use tarpc::trace::TraceId;
use tracing::Span;

/// Extracts and records RPC trace context on the current span.
///
/// Also emits a receive log with method and trace ID for client/daemon correlation.
pub fn setup_trace_context(ctx: &tarpc::context::Context, method: &'static str) {
    let trace_id = ctx.trace_context.trace_id;
    Span::current().record("trace_id", tracing::field::display(trace_id));
    tracing::info!(rpc.method = method, rpc.trace_id = %trace_id, "RPC: ReceiveRequest");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_setup_trace_context_from_tarpc_context() {
        let ctx = tarpc::context::current();
        setup_trace_context(&ctx, "DaemonApi.version");
        let trace_id = ctx.trace_context.trace_id;
        assert!(!trace_id.to_string().is_empty());
    }
}
