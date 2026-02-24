//! Tests for trace ID generation

mod common;

#[cfg(test)]
mod trace_tests {
    use std::cell::RefCell;

    use aranya_client::{config::CreateTeamQuicSyncConfig, CreateTeamConfig};
    use aranya_daemon_api::SEED_IKM_SIZE;
    use tempfile::TempDir;
    use tracing::info;
    // Test-only macro for capturing logs in tests.
    use tracing_test::traced_test;

    use crate::common::DeviceCtx;

    fn parse_trace_id(line: &str) -> Option<String> {
        let marker = "rpc.trace_id=";
        let start = line.find(marker)? + marker.len();
        let rest = &line[start..];
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        let raw = rest[..end].trim_matches(|c| c == '"' || c == ',' || c == '}' || c == ':');
        if raw.is_empty() {
            None
        } else {
            Some(raw.to_string())
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn test_basic_rpc_operations() -> anyhow::Result<()> {
        // Test that basic RPC operations work (RPC trace correlation is automatic via rpc_context)
        let work_dir = TempDir::new()?;
        let owner = DeviceCtx::new("trace-test", "owner", work_dir.path().join("owner")).await?;

        let seed_ikm = {
            let mut buf = [0u8; SEED_IKM_SIZE];
            owner.client.rand(&mut buf).await;
            buf
        };
        let qs_cfg = CreateTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        let owner_cfg = CreateTeamConfig::builder().quic_sync(qs_cfg).build()?;

        let team = owner.client.create_team(owner_cfg).await?;
        info!(team_id = %team.team_id(), "created team");

        let parsed = RefCell::new((None, Vec::new()));
        logs_assert(|lines: &[&str]| {
            let mut daemon_trace_id = None;
            let mut client_trace_ids = Vec::new();

            for line in lines.iter() {
                if line.contains("RPC: ReceiveRequest")
                    && (line.contains("create_team") || line.contains("DaemonApi.create_team"))
                {
                    if let Some(trace_id) = parse_trace_id(line) {
                        daemon_trace_id = Some(trace_id);
                    }
                }

                if line.contains("RPC: SendRequest")
                    && (line.contains("create_team") || line.contains("DaemonApi.create_team"))
                {
                    if let Some(trace_id) = parse_trace_id(line) {
                        client_trace_ids.push(trace_id);
                    }
                }
            }

            let Some(daemon_trace_id) = daemon_trace_id else {
                return Err("missing daemon trace id for create_team".to_string());
            };
            if client_trace_ids.is_empty() {
                return Err("missing client trace ids for create_team".to_string());
            }

            *parsed.borrow_mut() = (Some(daemon_trace_id), client_trace_ids);
            Ok(())
        });
        let (daemon_trace_id, client_trace_ids) = parsed.into_inner();
        let daemon_trace_id = daemon_trace_id.expect("daemon trace id should be captured");
        assert!(
            client_trace_ids.iter().any(|id| id == &daemon_trace_id),
            "daemon trace id not found in client logs"
        );
        let client_trace_id = client_trace_ids
            .iter()
            .find(|id| *id == &daemon_trace_id)
            .expect("matched client trace id should exist");
        info!(
            client_trace_id = %client_trace_id,
            daemon_trace_id = %daemon_trace_id,
            "trace id matched between client and daemon"
        );

        Ok(())
    }
}
