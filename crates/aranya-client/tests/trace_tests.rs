//! Test demonstrating distributed tracing with log output examples

mod common;

#[cfg(test)]
mod trace_tests {
    use aranya_client::{
        config::CreateTeamQuicSyncConfig, trace::generate_trace_id, CreateTeamConfig,
    };
    use aranya_daemon_api::SEED_IKM_SIZE;
    use tempfile::TempDir;
    use tracing::{debug, info};

    use crate::common::DeviceCtx;

    #[test_log::test(tokio::test)]
    async fn test_trace_id_in_logs() {
        let trace_id = generate_trace_id();
        info!(%trace_id, "starting test operation");

        debug!(%trace_id, "performing first RPC call");
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

        debug!(%trace_id, "performing second RPC call");
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

        info!(%trace_id, "test operation completed");
    }

    #[tokio::test]
    async fn test_create_team_rpc_correlation() -> anyhow::Result<()> {
        use crate::common::DevicesCtx;

        let create_team_trace_id = generate_trace_id();
        info!(%create_team_trace_id, "starting create_team operation");

        let work_dir = TempDir::new()?;
        let owner = DeviceCtx::new("trace-test", "owner", work_dir.path().join("owner")).await?;

        info!(%create_team_trace_id, owner_device_id = %owner.id, "owner device");

        let seed_ikm = {
            let mut buf = [0u8; SEED_IKM_SIZE];
            owner.client.rand(&mut buf).await;
            buf
        };
        let qs_cfg = CreateTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        let owner_cfg = CreateTeamConfig::builder().quic_sync(qs_cfg).build()?;

        debug!(%create_team_trace_id, "calling create_team RPC");
        let team = owner.client.create_team(owner_cfg).await?;
        info!(%create_team_trace_id, team_id = %team.team_id(), "created team in test");

        let devices = DevicesCtx::new("trace-test-multi").await?;
        info!(%create_team_trace_id, 
              owner_id = %devices.owner.id, 
              admin_id = %devices.admin.id,
              "initialized multiple devices");

        Ok(())
    }
}
