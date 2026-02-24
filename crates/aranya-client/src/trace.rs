//! Client-side RPC trace context utilities.
//!
//! This module provides helpers for generating trace IDs on the client side
//! and integrating them into tarpc contexts.

use rand::thread_rng;
pub use tarpc::trace::TraceId;

/// Generates a new trace ID and logs it.
///
/// This should be called at the start of a client operation to create
/// a unique trace ID for the entire operation. The returned trace ID
/// can then be passed to RPC calls via context metadata.
///
/// # Example
///
/// ```rust,ignore
/// use aranya_client::trace::generate_trace_id;
/// use tracing::info;
///
/// let trace_id = generate_trace_id();
/// info!(%trace_id, "starting operation");
/// // Use trace_id for RPC calls...
/// ```
pub fn generate_trace_id() -> TraceId {
    let mut rng = thread_rng();
    let trace_id = TraceId::random(&mut rng);
    tracing::debug!(trace_id = %trace_id, "generated trace ID");
    trace_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_id_creation() {
        let trace_id = generate_trace_id();
        assert!(!trace_id.to_string().is_empty());
    }
}
