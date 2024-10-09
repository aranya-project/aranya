//! Integration tests for the user library.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    rust_2018_idioms
)]

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use aranya_client::Client;
use aranya_daemon::{addr::Addr, config::Config, Daemon};
use aranya_daemon_api::{Addr as ApiAddr, DeviceId, KeyBundle, Role};
use backon::{ExponentialBuilder, Retryable};
use tempfile::tempdir;
use test_log::test;
use tokio::{fs, task, time::sleep};
use tracing::info;

struct TeamCtx {
    owner: UserCtx,
    admin: UserCtx,
    operator: UserCtx,
    member: UserCtx,
}

impl TeamCtx {
    pub async fn new(work_dir: PathBuf) -> Result<Self> {
        let owner = UserCtx::new(work_dir.join("owner"), 10010).await?;
        let admin = UserCtx::new(work_dir.join("admin"), 10011).await?;
        let operator = UserCtx::new(work_dir.join("operator"), 10012).await?;
        let member = UserCtx::new(work_dir.join("member"), 10013).await?;

        Ok(Self {
            owner,
            admin,
            operator,
            member,
        })
    }
}

struct UserCtx {
    client: Client,
    pk: KeyBundle,
    id: DeviceId,
    cfg: Config,
}

impl UserCtx {
    pub async fn new(work_dir: PathBuf, port: u16) -> Result<Self> {
        fs::create_dir_all(work_dir.clone()).await?;

        // Setup daemon config.
        let uds_api_path = work_dir.join("uds.sock");
        let sync_addr = Addr::new("localhost", port).expect("should be able to create new Addr");
        let cfg = Config {
            name: "daemon".into(),
            work_dir: work_dir.clone(),
            uds_api_path: uds_api_path.clone(),
            pid_file: work_dir.join("pid"),
            sync_addr,
        };
        // Load daemon from config.
        let daemon = Daemon::load(cfg.clone())
            .await
            .context("unable to init daemon")?;
        // Start daemon.
        task::spawn(async move {
            daemon
                .run()
                .await
                .expect("expected no errors running daemon")
        });
        // give daemon time to setup UDS API.
        sleep(Duration::from_millis(100)).await;

        // Initialize the user library.
        let mut client = (|| Client::connect(&uds_api_path))
            .retry(ExponentialBuilder::default())
            .await
            .context("unable to init client")?;

        // Perform setup of a team.
        client
            .initialize()
            .await
            .expect("expected to initialize daemon");

        // Get device id and key bundle.
        let pk = client.get_key_bundle().await.expect("expected key bundle");
        let id = client.get_device_id().await.expect("expected device id");

        Ok(Self {
            client,
            pk,
            id,
            cfg,
        })
    }
}

/// Integration test for the user library and daemon.
/// Tests creating a team with the user library.
/// More extensive integration testing is conducted inside the daemon crate.
/// The goal of this integration test is to validate the user library's end-to-end functionality.
/// This includes exercising the user library's idiomatic Rust API as well as the daemon's `tarpc` API.
///
/// Example of debugging test with tracing:
/// `ARANYA_DAEMON="debug" RUST_LOG="debug" cargo test integration_test -- --show-output --nocapture`
#[test(tokio::test(flavor = "multi_thread"))]
async fn integration_test() -> Result<()> {
    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new(work_dir).await?;

    // create team.
    let team_id = team
        .owner
        .client
        .create_team()
        .await
        .expect("expected to create team");
    info!(?team_id);

    // setup sync peers.
    let mut owner_team = team.owner.client.team(team_id);
    let mut admin_team = team.admin.client.team(team_id);
    let mut operator_team = team.operator.client.team(team_id);
    let mut member_team = team.member.client.team(team_id);

    let interval = Duration::from_millis(100);
    owner_team
        .add_sync_peer(ApiAddr(team.admin.cfg.sync_addr.to_string()), interval)
        .await?;
    owner_team
        .add_sync_peer(ApiAddr(team.operator.cfg.sync_addr.to_string()), interval)
        .await?;
    owner_team
        .add_sync_peer(ApiAddr(team.member.cfg.sync_addr.to_string()), interval)
        .await?;

    admin_team
        .add_sync_peer(ApiAddr(team.owner.cfg.sync_addr.to_string()), interval)
        .await?;
    admin_team
        .add_sync_peer(ApiAddr(team.operator.cfg.sync_addr.to_string()), interval)
        .await?;
    admin_team
        .add_sync_peer(ApiAddr(team.member.cfg.sync_addr.to_string()), interval)
        .await?;

    operator_team
        .add_sync_peer(ApiAddr(team.owner.cfg.sync_addr.to_string()), interval)
        .await?;
    operator_team
        .add_sync_peer(ApiAddr(team.admin.cfg.sync_addr.to_string()), interval)
        .await?;
    operator_team
        .add_sync_peer(ApiAddr(team.member.cfg.sync_addr.to_string()), interval)
        .await?;

    member_team
        .add_sync_peer(ApiAddr(team.owner.cfg.sync_addr.to_string()), interval)
        .await?;
    member_team
        .add_sync_peer(ApiAddr(team.admin.cfg.sync_addr.to_string()), interval)
        .await?;
    member_team
        .add_sync_peer(ApiAddr(team.operator.cfg.sync_addr.to_string()), interval)
        .await?;

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk).await?;
    owner_team.assign_role(team.admin.id, Role::Admin).await?;

    // wait for syncing.
    sleep(interval * 3).await;

    // add operator to team.
    info!("adding operator to team");
    owner_team.add_device_to_team(team.operator.pk).await?;

    // wait for syncing.
    sleep(interval * 3).await;

    admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await?;

    // wait for syncing.
    sleep(interval * 3).await;

    // add member to team.
    info!("adding member to team");
    operator_team.add_device_to_team(team.member.pk).await?;

    // wait for syncing.
    sleep(interval * 3).await;

    // remove devices from team.
    info!("removing member");
    owner_team.remove_device_from_team(team.member.id).await?;
    info!("removing operator");
    owner_team
        .revoke_role(team.operator.id, Role::Operator)
        .await?;
    owner_team.remove_device_from_team(team.operator.id).await?;
    info!("removing admin");
    owner_team.revoke_role(team.admin.id, Role::Admin).await?;
    owner_team.remove_device_from_team(team.admin.id).await?;

    Ok(())
}
