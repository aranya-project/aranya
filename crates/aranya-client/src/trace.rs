//! Client-side RPC trace context utilities.
//!
//! This module provides helpers for generating trace IDs on the client side
//! and integrating them into tarpc contexts.

use aranya_crypto::{Csprng, Rng};
use std::sync::Arc;

/// A unique identifier for correlating RPC requests across the system.
///
/// Generated on the client side and included in tarpc context metadata
/// to enable end-to-end request tracing from client through daemon.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceId(Arc<str>);

impl TraceId {
    /// Generates a new trace ID using cryptographic randomness.
    pub fn new() -> Self {
        let mut bytes = [0u8; 16];
        Rng.fill_bytes(&mut bytes);
        // Format as 32-character hex string (128 bits)
        let hex = bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        Self(Arc::from(hex))
    }

    /// Creates a trace ID from a string.
    pub fn from_str(id: impl Into<String>) -> Self {
        Self(Arc::from(id.into()))
    }

    /// Returns the trace ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&str> for TraceId {
    fn from(s: &str) -> Self {
        Self::from_str(s.to_string())
    }
}

impl From<String> for TraceId {
    fn from(s: String) -> Self {
        Self::from_str(s)
    }
}

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
    let trace_id = TraceId::new();
    tracing::debug!(trace_id = %trace_id, "generated trace ID");
    trace_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_id_creation() {
        let trace_id = TraceId::from_str("test-123");
        assert_eq!(trace_id.as_str(), "test-123");
    }

    #[test]
    fn test_trace_id_from_string() {
        let s = String::from("test-456");
        let trace_id = TraceId::from(s);
        assert_eq!(trace_id.as_str(), "test-456");
    }

    #[test]
    fn test_trace_id_from_str() {
        let trace_id = TraceId::from("test-789");
        assert_eq!(trace_id.as_str(), "test-789");
    }

    #[test]
    fn test_trace_id_display() {
        let trace_id = TraceId::from_str("test-display");
        assert_eq!(trace_id.to_string(), "test-display");
    }
}
