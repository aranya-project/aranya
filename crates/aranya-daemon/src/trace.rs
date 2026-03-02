//! Distributed tracing context utilities.
//!
//! This module provides helpers for propagating RPC trace IDs
//! throughout the daemon's execution.

pub use tarpc::trace::TraceId;
use tracing::Span;

/// Records the trace ID on the current span.
pub fn record_current_span_trace_id(trace_id: TraceId) {
    Span::current().record("trace_id", tracing::field::display(trace_id));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_trace_id_creation() {
        let trace_id = TraceId::default();
        assert!(!trace_id.to_string().is_empty());
    }
}
