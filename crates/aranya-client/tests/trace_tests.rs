//! Tests for trace ID generation

mod common;

#[cfg(test)]
mod trace_tests {
    use aranya_client::{
        config::CreateTeamQuicSyncConfig, trace::generate_trace_id, CreateTeamConfig,
    };
    use aranya_daemon_api::SEED_IKM_SIZE;
    use tempfile::TempDir;
    use tracing::info;

    use crate::common::DeviceCtx;

    #[test_log::test(tokio::test)]
    async fn test_trace_id_generation() {
        // Test that trace IDs can be generated and logged
        let trace_id = generate_trace_id();
        info!(%trace_id, "generated trace ID");

        let trace_id2 = generate_trace_id();
        info!(%trace_id2, "generated second trace ID");

        // Verify they're different
        assert_ne!(trace_id.as_str(), trace_id2.as_str());
    }

    #[tokio::test]
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

        Ok(())
    }
}
