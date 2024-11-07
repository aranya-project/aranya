//! Integration tests for the user library.

#![allow(
    clippy::disallowed_macros,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    rust_2018_idioms
)]

use core::str;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use aranya_client::Client;
use aranya_daemon::{
    config::{AfcConfig, Config},
    Daemon,
};
use aranya_daemon_api::{DeviceId, KeyBundle, NetIdentifier, Role};
use aranya_fast_channels::Label;
use aranya_util::addr::Addr;
use backon::{ExponentialBuilder, Retryable};
use tempfile::tempdir;
use test_log::test;
use tokio::{fs, task, time::sleep};
use tracing::{debug, info};

struct TeamCtx {
    owner: UserCtx,
    admin: UserCtx,
    operator: UserCtx,
    membera: UserCtx,
    memberb: UserCtx,
}

impl TeamCtx {
    pub async fn new(name: String, work_dir: PathBuf) -> Result<Self> {
        let owner = UserCtx::new(name.clone(), "owner".into(), work_dir.join("owner")).await?;
        let admin = UserCtx::new(name.clone(), "admin".into(), work_dir.join("admin")).await?;
        let operator =
            UserCtx::new(name.clone(), "operator".into(), work_dir.join("operator")).await?;
        let membera =
            UserCtx::new(name.clone(), "membera".into(), work_dir.join("membera")).await?;
        let memberb =
            UserCtx::new(name.clone(), "memberb".into(), work_dir.join("memberb")).await?;

        Ok(Self {
            owner,
            admin,
            operator,
            membera,
            memberb,
        })
    }
}

struct UserCtx {
    client: Client,
    pk: KeyBundle,
    id: DeviceId,
}

impl UserCtx {
    pub async fn new(team_name: String, name: String, work_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(work_dir.clone()).await?;

        // Setup daemon config.
        let uds_api_path = work_dir.join("uds.sock");
        let any = Addr::new("localhost", 0).expect("should be able to create new Addr");
        let shm_path = format!("/shm_{}_{}", team_name, name).to_string();
        let max_chans = 100;
        let cfg = Config {
            name: "daemon".into(),
            work_dir: work_dir.clone(),
            uds_api_path: uds_api_path.clone(),
            pid_file: work_dir.join("pid"),
            sync_addr: any,
            afc: AfcConfig {
                shm_path: shm_path.clone(),
                unlink_on_startup: true,
                unlink_at_exit: true,
                create: true,
                max_chans,
            },
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
        let mut client = (|| Client::connect(&uds_api_path, Path::new(&shm_path), max_chans, any))
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

        Ok(Self { client, pk, id })
    }

    async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.aranya_local_addr().await?)
    }

    async fn afc_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.afc_local_addr().await?)
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
    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("integration_test".into(), work_dir).await?;

    // create team.
    let team_id = team
        .owner
        .client
        .create_team()
        .await
        .expect("expected to create team");
    info!(?team_id);
    // TODO: implement add_team.
    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    */

    // get sync addresses.
    let owner_addr = team.owner.aranya_local_addr().await?;
    let admin_addr = team.admin.aranya_local_addr().await?;
    let operator_addr = team.operator.aranya_local_addr().await?;
    let membera_addr = team.membera.aranya_local_addr().await?;

    // setup sync peers.
    let mut owner_team = team.owner.client.team(team_id);
    let mut admin_team = team.admin.client.team(team_id);
    let mut operator_team = team.operator.client.team(team_id);
    let mut member_team = team.membera.client.team(team_id);

    owner_team
        .add_sync_peer(admin_addr.into(), sync_interval)
        .await?;
    owner_team
        .add_sync_peer(operator_addr.into(), sync_interval)
        .await?;
    owner_team
        .add_sync_peer(membera_addr.into(), sync_interval)
        .await?;

    admin_team
        .add_sync_peer(owner_addr.into(), sync_interval)
        .await?;
    admin_team
        .add_sync_peer(operator_addr.into(), sync_interval)
        .await?;
    admin_team
        .add_sync_peer(membera_addr.into(), sync_interval)
        .await?;

    operator_team
        .add_sync_peer(owner_addr.into(), sync_interval)
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_interval)
        .await?;
    operator_team
        .add_sync_peer(membera_addr.into(), sync_interval)
        .await?;

    member_team
        .add_sync_peer(owner_addr.into(), sync_interval)
        .await?;
    member_team
        .add_sync_peer(admin_addr.into(), sync_interval)
        .await?;
    member_team
        .add_sync_peer(operator_addr.into(), sync_interval)
        .await?;

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk).await?;
    owner_team.assign_role(team.admin.id, Role::Admin).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add operator to team.
    info!("adding operator to team");
    owner_team.add_device_to_team(team.operator.pk).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add member to team.
    info!("adding member to team");
    operator_team.add_device_to_team(team.membera.pk).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // remove devices from team.
    info!("removing member");
    owner_team.remove_device_from_team(team.membera.id).await?;
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

/// Tests Aranya Fast Channels data plane.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_afc() -> Result<()> {
    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_afc_router".into(), work_dir).await?;

    // create team.
    let team_id = team
        .owner
        .client
        .create_team()
        .await
        .expect("expected to create team");
    info!(?team_id);
    // TODO: implement add_team.
    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

    // get sync addresses.
    let owner_addr = team.owner.aranya_local_addr().await?;
    let admin_addr = team.admin.aranya_local_addr().await?;
    let operator_addr = team.operator.aranya_local_addr().await?;
    let membera_addr = team.membera.aranya_local_addr().await?;
    let memberb_addr = team.memberb.aranya_local_addr().await?;

    // get afc addresses.
    let membera_afc_addr = team.membera.afc_local_addr().await?;
    let memberb_afc_addr = team.memberb.afc_local_addr().await?;

    // setup sync peers.
    let mut owner_team = team.owner.client.team(team_id);
    let mut admin_team = team.admin.client.team(team_id);
    let mut operator_team = team.operator.client.team(team_id);
    let mut membera_team = team.membera.client.team(team_id);
    let mut memberb_team = team.memberb.client.team(team_id);

    owner_team
        .add_sync_peer(admin_addr.into(), sync_interval)
        .await?;
    owner_team
        .add_sync_peer(operator_addr.into(), sync_interval)
        .await?;
    owner_team
        .add_sync_peer(membera_addr.into(), sync_interval)
        .await?;

    admin_team
        .add_sync_peer(owner_addr.into(), sync_interval)
        .await?;
    admin_team
        .add_sync_peer(operator_addr.into(), sync_interval)
        .await?;
    admin_team
        .add_sync_peer(membera_addr.into(), sync_interval)
        .await?;

    operator_team
        .add_sync_peer(owner_addr.into(), sync_interval)
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_interval)
        .await?;
    operator_team
        .add_sync_peer(membera_addr.into(), sync_interval)
        .await?;

    membera_team
        .add_sync_peer(owner_addr.into(), sync_interval)
        .await?;
    membera_team
        .add_sync_peer(admin_addr.into(), sync_interval)
        .await?;
    membera_team
        .add_sync_peer(operator_addr.into(), sync_interval)
        .await?;
    membera_team
        .add_sync_peer(memberb_addr.into(), sync_interval)
        .await?;

    memberb_team
        .add_sync_peer(owner_addr.into(), sync_interval)
        .await?;
    memberb_team
        .add_sync_peer(admin_addr.into(), sync_interval)
        .await?;
    memberb_team
        .add_sync_peer(operator_addr.into(), sync_interval)
        .await?;
    memberb_team
        .add_sync_peer(membera_addr.into(), sync_interval)
        .await?;

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk).await?;
    owner_team.assign_role(team.admin.id, Role::Admin).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add operator to team.
    info!("adding operator to team");
    owner_team.add_device_to_team(team.operator.pk).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add membera to team.
    info!("adding membera to team");
    operator_team.add_device_to_team(team.membera.pk).await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator_team.add_device_to_team(team.memberb.pk).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // operator assigns labels for AFC channels.
    let label1 = Label::new(1);
    operator_team.create_label(label1).await?;
    operator_team.assign_label(team.membera.id, label1).await?;
    operator_team.assign_label(team.memberb.id, label1).await?;

    let label2 = Label::new(2);
    operator_team.create_label(label2).await?;
    operator_team.assign_label(team.membera.id, label2).await?;
    operator_team.assign_label(team.memberb.id, label2).await?;

    // assign network addresses.
    operator_team
        .assign_net_name(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
        .await?;
    operator_team
        .assign_net_name(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // membera creates bidi channel with memberb
    let afc_id1 = team
        .membera
        .client
        .create_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label1)
        .await?;

    // membera creates bidi channel with memberb
    let afc_id2 = team
        .membera
        .client
        .create_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label2)
        .await?;

    // wait for ctrl message to be sent.
    sleep(Duration::from_millis(100)).await;

    // poll for ctrl message.
    // TODO: poll in a separate task.
    debug!("poll to send ctrl msg");
    team.membera.client.poll().await?;
    debug!("poll to recv ctrl msg");
    team.memberb.client.poll().await?;
    debug!("poll to recv ctrl msg");
    team.memberb.client.poll().await?;

    // poll for ctrl message.
    // TODO: poll in a separate task.
    debug!("poll to send ctrl msg");
    team.membera.client.poll().await?;
    debug!("poll to recv ctrl msg");
    team.memberb.client.poll().await?;
    debug!("poll to recv ctrl msg");
    team.memberb.client.poll().await?;

    let msg = "hello world label1";
    team.membera.client.send_data(afc_id1, msg.into()).await?;
    debug!(?msg, "sent message");

    let msg = "hello world label2";
    team.membera.client.send_data(afc_id2, msg.into()).await?;
    debug!(?msg, "sent message");

    // poll for data message.
    debug!("polling to send data msg");
    team.membera.client.poll().await?;
    debug!("polling to recv data msg");
    team.memberb.client.poll().await?;

    // poll for data message.
    debug!("polling to send data msg");
    team.membera.client.poll().await?;
    debug!("polling to recv data msg");
    team.memberb.client.poll().await?;

    let (data, _addr, _afc_id, label) = team.memberb.client.recv_data().await?;
    debug!(
        n = data.len(),
        ?label,
        "received message: {:?}",
        str::from_utf8(&data)?
    );

    let (data, _addr, _afc_id, label) = team.memberb.client.recv_data().await?;
    debug!(
        n = data.len(),
        ?label,
        "received message: {:?}",
        str::from_utf8(&data)?
    );

    Ok(())
}
