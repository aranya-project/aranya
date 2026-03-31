//! Structured observability events and required fields.

use std::time::Instant;

use tarpc::trace::TraceId;

/// Top-level JSON key carrying event timestamp.
pub const ROOT_TIMESTAMP: &str = "timestamp";
/// Top-level JSON key carrying event level.
pub const ROOT_LEVEL: &str = "level";
/// Top-level JSON key carrying event target/module.
pub const ROOT_TARGET: &str = "target";
/// Top-level JSON key carrying all structured fields.
pub const ROOT_FIELDS: &str = "fields";
/// Structured message field inside `fields`.
pub const FIELD_MESSAGE: &str = "message";

/// Event field carrying the event name.
pub const FIELD_EVENT_NAME: &str = "event.name";
/// Event field carrying the daemon component name.
pub const FIELD_SERVICE_COMPONENT: &str = "service.component";
/// Event field carrying the daemon instance name.
pub const FIELD_DAEMON_NAME: &str = "daemon.name";
/// Event field carrying the RPC trace ID.
pub const FIELD_RPC_TRACE_ID: &str = "rpc.trace_id";
/// Event field carrying the RPC deadline.
pub const FIELD_RPC_DEADLINE: &str = "rpc.deadline";
/// Event field carrying OpenTelemetry span kind.
pub const FIELD_OTEL_KIND: &str = "otel.kind";
/// Event field carrying OpenTelemetry operation name.
pub const FIELD_OTEL_NAME: &str = "otel.name";

/// Team context field.
pub const FIELD_TEAM: &str = "team";
/// Device context field.
pub const FIELD_DEVICE: &str = "device";
/// Device ID context field.
pub const FIELD_DEVICE_ID: &str = "device_id";
/// Role context field.
pub const FIELD_ROLE: &str = "role";
/// Role ID context field.
pub const FIELD_ROLE_ID: &str = "role_id";
/// Label context field.
pub const FIELD_LABEL: &str = "label";
/// Label ID context field.
pub const FIELD_LABEL_ID: &str = "label_id";
/// Peer sync context field.
pub const FIELD_PEER: &str = "peer";
/// Graph sync context field.
pub const FIELD_GRAPH: &str = "graph";
/// Command count sync context field.
pub const FIELD_CMD_COUNT: &str = "cmd_count";
/// Effect count sync context field.
pub const FIELD_EFFECTS_COUNT: &str = "effects_count";
/// Top-level error message field.
pub const FIELD_ERROR: &str = "error";

/// The daemon component value used for observability events.
pub const SERVICE_COMPONENT_DAEMON: &str = "daemon";
/// OpenTelemetry server span kind value.
pub const OTEL_KIND_SERVER: &str = "server";
/// OpenTelemetry client span kind value.
pub const OTEL_KIND_CLIENT: &str = "client";

/// Global required observability fields for all daemon logs.
pub const REQUIRED_ROOT_FIELDS: &[&str] = &[ROOT_TIMESTAMP, ROOT_LEVEL, ROOT_TARGET, ROOT_FIELDS];
/// Required base structured fields for all observability events.
pub const REQUIRED_BASE_EVENT_FIELDS: &[&str] =
    &[FIELD_MESSAGE, FIELD_EVENT_NAME, FIELD_SERVICE_COMPONENT];
/// Required RPC correlation fields.
pub const REQUIRED_RPC_FIELDS: &[&str] = &[
    FIELD_RPC_TRACE_ID,
    FIELD_RPC_DEADLINE,
    FIELD_OTEL_KIND,
    FIELD_OTEL_NAME,
];
/// Operation context fields for team and object operations.
pub const TEAM_OBJECT_CONTEXT_FIELDS: &[&str] = &[
    FIELD_TEAM,
    FIELD_DEVICE,
    FIELD_DEVICE_ID,
    FIELD_ROLE,
    FIELD_ROLE_ID,
    FIELD_LABEL,
    FIELD_LABEL_ID,
];
/// Operation context fields for sync operations.
pub const SYNC_CONTEXT_FIELDS: &[&str] = &[
    FIELD_PEER,
    FIELD_GRAPH,
    FIELD_CMD_COUNT,
    FIELD_EFFECTS_COUNT,
];
/// Required fields for error observability events.
pub const ERROR_EVENT_REQUIRED_FIELDS: &[&str] =
    &[FIELD_ERROR, FIELD_RPC_TRACE_ID, FIELD_OTEL_NAME];

/// Observability events emitted by the daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservabilityEvent {
    /// Daemon process startup event.
    DaemonStarting,
    /// Daemon initialization completed event.
    DaemonLoaded,
    /// Incoming RPC request event.
    RpcReceiveRequest,
    /// Test-only RPC trace ID echo event.
    RpcTestTraceId,
}

impl ObservabilityEvent {
    /// Stable event name used in structured logs.
    pub const fn event_name(self) -> &'static str {
        match self {
            Self::DaemonStarting => "daemon.starting",
            Self::DaemonLoaded => "daemon.loaded",
            Self::RpcReceiveRequest => "rpc.receive_request",
            Self::RpcTestTraceId => "rpc.test_trace_id",
        }
    }

    /// Required structured fields for this event.
    pub const fn required_fields(self) -> &'static [&'static str] {
        match self {
            Self::DaemonStarting | Self::DaemonLoaded => &[
                FIELD_MESSAGE,
                FIELD_EVENT_NAME,
                FIELD_SERVICE_COMPONENT,
                FIELD_DAEMON_NAME,
            ],
            Self::RpcReceiveRequest | Self::RpcTestTraceId => &[
                FIELD_MESSAGE,
                FIELD_EVENT_NAME,
                FIELD_SERVICE_COMPONENT,
                FIELD_RPC_TRACE_ID,
                FIELD_RPC_DEADLINE,
                FIELD_OTEL_KIND,
                FIELD_OTEL_NAME,
            ],
        }
    }
}

fn contains_all_fields(haystack: &[&str], required: &[&str]) -> bool {
    required.iter().all(|f| haystack.contains(f))
}

/// Returns `true` if an event's required fields include all provided fields.
pub fn event_satisfies_required_fields(
    event: ObservabilityEvent,
    required_fields: &[&str],
) -> bool {
    contains_all_fields(event.required_fields(), required_fields)
}

/// Performs a one-time observability required-fields validation.
///
/// This is intended for startup checks.
pub fn startup_event_check() -> Result<(), &'static str> {
    for event in [
        ObservabilityEvent::DaemonStarting,
        ObservabilityEvent::DaemonLoaded,
        ObservabilityEvent::RpcReceiveRequest,
        ObservabilityEvent::RpcTestTraceId,
    ] {
        if !event_satisfies_required_fields(event, REQUIRED_BASE_EVENT_FIELDS) {
            return Err("event does not satisfy base required fields");
        }
    }

    for event in [
        ObservabilityEvent::RpcReceiveRequest,
        ObservabilityEvent::RpcTestTraceId,
    ] {
        if !event_satisfies_required_fields(event, REQUIRED_RPC_FIELDS) {
            return Err("rpc event does not satisfy rpc required fields");
        }
    }

    Ok(())
}

/// Returns `true` if the provided OpenTelemetry kind is supported.
pub fn is_valid_otel_kind(kind: &str) -> bool {
    matches!(kind, OTEL_KIND_SERVER | OTEL_KIND_CLIENT)
}

/// Returns `true` if daemon-level observability inputs are valid.
pub fn validate_daemon_inputs(name: &str) -> bool {
    !name.trim().is_empty()
}

/// Returns `true` if RPC observability inputs are valid.
pub fn validate_rpc_inputs(trace_id: &str, otel_kind: &str, otel_name: &str) -> bool {
    !trace_id.trim().is_empty() && is_valid_otel_kind(otel_kind) && !otel_name.trim().is_empty()
}

/// Emit a daemon-starting observability event.
pub fn log_daemon_starting(name: &str) {
    debug_assert!(
        event_satisfies_required_fields(
            ObservabilityEvent::DaemonStarting,
            REQUIRED_BASE_EVENT_FIELDS
        ),
        "daemon.starting must satisfy base required fields"
    );
    debug_assert!(
        validate_daemon_inputs(name),
        "daemon.name must not be empty"
    );
    tracing::info!(
        event.name = ObservabilityEvent::DaemonStarting.event_name(),
        service.component = SERVICE_COMPONENT_DAEMON,
        daemon.name = %name,
        "starting Aranya daemon"
    );
}

/// Emit a daemon-loaded observability event.
pub fn log_daemon_loaded(name: &str) {
    debug_assert!(
        event_satisfies_required_fields(
            ObservabilityEvent::DaemonLoaded,
            REQUIRED_BASE_EVENT_FIELDS
        ),
        "daemon.loaded must satisfy base required fields"
    );
    debug_assert!(
        validate_daemon_inputs(name),
        "daemon.name must not be empty"
    );
    tracing::info!(
        event.name = ObservabilityEvent::DaemonLoaded.event_name(),
        service.component = SERVICE_COMPONENT_DAEMON,
        daemon.name = %name,
        "loaded Aranya daemon"
    );
}

/// Emit an RPC receive observability event.
pub fn log_rpc_receive_request(
    trace_id: TraceId,
    rpc_deadline: Instant,
    otel_kind: &str,
    otel_name: &str,
) {
    let trace_id_s = trace_id.to_string();
    debug_assert!(
        event_satisfies_required_fields(
            ObservabilityEvent::RpcReceiveRequest,
            REQUIRED_BASE_EVENT_FIELDS
        ),
        "rpc.receive_request must satisfy base required fields"
    );
    debug_assert!(
        event_satisfies_required_fields(ObservabilityEvent::RpcReceiveRequest, REQUIRED_RPC_FIELDS),
        "rpc.receive_request must satisfy RPC required fields"
    );
    debug_assert!(
        validate_rpc_inputs(&trace_id_s, otel_kind, otel_name),
        "rpc observability inputs are invalid"
    );
    tracing::info!(
        event.name = ObservabilityEvent::RpcReceiveRequest.event_name(),
        service.component = SERVICE_COMPONENT_DAEMON,
        rpc.trace_id = %trace_id,
        rpc.deadline = ?rpc_deadline,
        otel.kind = %otel_kind,
        otel.name = %otel_name,
        "RPC: ReceiveRequest"
    );
}

/// Emit a test-only RPC trace event.
pub fn log_rpc_test_trace_id(
    trace_id: &str,
    rpc_deadline: Instant,
    otel_kind: &str,
    otel_name: &str,
) {
    debug_assert!(
        event_satisfies_required_fields(
            ObservabilityEvent::RpcTestTraceId,
            REQUIRED_BASE_EVENT_FIELDS
        ),
        "rpc.test_trace_id must satisfy base required fields"
    );
    debug_assert!(
        event_satisfies_required_fields(ObservabilityEvent::RpcTestTraceId, REQUIRED_RPC_FIELDS),
        "rpc.test_trace_id must satisfy RPC required fields"
    );
    debug_assert!(
        validate_rpc_inputs(trace_id, otel_kind, otel_name),
        "rpc observability inputs are invalid"
    );
    tracing::info!(
        event.name = ObservabilityEvent::RpcTestTraceId.event_name(),
        service.component = SERVICE_COMPONENT_DAEMON,
        rpc.trace_id = %trace_id,
        rpc.deadline = ?rpc_deadline,
        otel.kind = %otel_kind,
        otel.name = %otel_name,
        "RPC: TestTraceId"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_fields_declared() {
        assert!(REQUIRED_ROOT_FIELDS.contains(&ROOT_TIMESTAMP));
        assert!(REQUIRED_ROOT_FIELDS.contains(&ROOT_LEVEL));
        assert!(REQUIRED_ROOT_FIELDS.contains(&ROOT_TARGET));

        assert!(REQUIRED_BASE_EVENT_FIELDS.contains(&FIELD_MESSAGE));
        assert!(REQUIRED_BASE_EVENT_FIELDS.contains(&FIELD_EVENT_NAME));
        assert!(REQUIRED_BASE_EVENT_FIELDS.contains(&FIELD_SERVICE_COMPONENT));

        assert!(REQUIRED_RPC_FIELDS.contains(&FIELD_RPC_TRACE_ID));
        assert!(REQUIRED_RPC_FIELDS.contains(&FIELD_RPC_DEADLINE));
        assert!(REQUIRED_RPC_FIELDS.contains(&FIELD_OTEL_KIND));
        assert!(REQUIRED_RPC_FIELDS.contains(&FIELD_OTEL_NAME));

        assert!(TEAM_OBJECT_CONTEXT_FIELDS.contains(&FIELD_TEAM));
        assert!(TEAM_OBJECT_CONTEXT_FIELDS.contains(&FIELD_DEVICE));
        assert!(TEAM_OBJECT_CONTEXT_FIELDS.contains(&FIELD_DEVICE_ID));
        assert!(TEAM_OBJECT_CONTEXT_FIELDS.contains(&FIELD_ROLE));
        assert!(TEAM_OBJECT_CONTEXT_FIELDS.contains(&FIELD_ROLE_ID));
        assert!(TEAM_OBJECT_CONTEXT_FIELDS.contains(&FIELD_LABEL));
        assert!(TEAM_OBJECT_CONTEXT_FIELDS.contains(&FIELD_LABEL_ID));

        assert!(SYNC_CONTEXT_FIELDS.contains(&FIELD_PEER));
        assert!(SYNC_CONTEXT_FIELDS.contains(&FIELD_GRAPH));
        assert!(SYNC_CONTEXT_FIELDS.contains(&FIELD_CMD_COUNT));
        assert!(SYNC_CONTEXT_FIELDS.contains(&FIELD_EFFECTS_COUNT));

        assert!(ERROR_EVENT_REQUIRED_FIELDS.contains(&FIELD_ERROR));
        assert!(ERROR_EVENT_REQUIRED_FIELDS.contains(&FIELD_RPC_TRACE_ID));
        assert!(ERROR_EVENT_REQUIRED_FIELDS.contains(&FIELD_OTEL_NAME));
    }

    #[test]
    fn test_event_required_fields_satisfied() {
        assert!(event_satisfies_required_fields(
            ObservabilityEvent::DaemonStarting,
            REQUIRED_BASE_EVENT_FIELDS,
        ));
        assert!(event_satisfies_required_fields(
            ObservabilityEvent::DaemonLoaded,
            REQUIRED_BASE_EVENT_FIELDS,
        ));
        assert!(event_satisfies_required_fields(
            ObservabilityEvent::RpcReceiveRequest,
            REQUIRED_BASE_EVENT_FIELDS,
        ));
        assert!(event_satisfies_required_fields(
            ObservabilityEvent::RpcReceiveRequest,
            REQUIRED_RPC_FIELDS,
        ));
        assert!(event_satisfies_required_fields(
            ObservabilityEvent::RpcTestTraceId,
            REQUIRED_BASE_EVENT_FIELDS,
        ));
        assert!(event_satisfies_required_fields(
            ObservabilityEvent::RpcTestTraceId,
            REQUIRED_RPC_FIELDS,
        ));
    }

    #[test]
    fn test_startup_required_fields_check() {
        assert!(startup_required_fields_check().is_ok());
    }

    #[test]
    fn test_validate_daemon_inputs() {
        assert!(validate_daemon_inputs("daemon-a"));
        assert!(!validate_daemon_inputs(""));
        assert!(!validate_daemon_inputs("   "));
    }

    #[test]
    fn test_validate_rpc_inputs() {
        let ctx = tarpc::context::current();
        let trace_id = ctx.trace_context.trace_id;
        let trace_id = trace_id.to_string();

        assert!(validate_rpc_inputs(
            &trace_id,
            OTEL_KIND_SERVER,
            ObservabilityEvent::RpcReceiveRequest.event_name()
        ));
        assert!(validate_rpc_inputs(
            &trace_id,
            OTEL_KIND_CLIENT,
            ObservabilityEvent::RpcTestTraceId.event_name()
        ));

        assert!(!validate_rpc_inputs(
            "",
            OTEL_KIND_SERVER,
            ObservabilityEvent::RpcReceiveRequest.event_name()
        ));
        assert!(!validate_rpc_inputs(
            &trace_id,
            "invalid",
            ObservabilityEvent::RpcReceiveRequest.event_name()
        ));
        assert!(!validate_rpc_inputs(&trace_id, OTEL_KIND_SERVER, ""));
    }
}
