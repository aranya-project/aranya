//! Member A device.

use std::path::PathBuf;

use anyhow::Result;
use aranya_client::{AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
use aranya_daemon_api::{NetIdentifier, Role};
use aranya_example_multi_node::{
    env::EnvVars,
    onboarding::{DeviceInfo, Onboard, TeamInfo, SLEEP_INTERVAL, SYNC_INTERVAL},
    tracing::init_tracing,
};
use backon::{ExponentialBuilder, Retryable};
use bytes::Bytes;
use clap::Parser;
use tokio::time::sleep;
use tracing::info;

/// CLI args.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Daemon UDS socket path.
    #[arg(long)]
    uds_sock: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!("starting aranya-example-multi-node-membera");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Start TCP server.
    info!("membera: starting onboarding server");
    let onboard = Onboard::new(env.membera.tcp_addr, env.passphrase).await?;
    info!("membera: started onboarding server");

    // Initialize client.
    info!("membera: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&args.uds_sock)
            .aqc_server_addr(&env.membera.aqc_addr)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("membera: initialized client");

    // Get team info from owner.
    let team_info: TeamInfo = onboard.recv().await?;
    info!("membera: received team info from owner");

    // Add team.
    let add_team_cfg = {
        let qs_cfg = AddTeamQuicSyncConfig::builder()
            .seed_ikm(team_info.seed_ikm)
            .build()?;
        AddTeamConfig::builder()
            .quic_sync(qs_cfg)
            .team_id(team_info.team_id)
            .build()?
    };
    let team = client
        .add_team(add_team_cfg.clone())
        .await
        .expect("expected to add team");
    info!("membera: added team");

    // Send device info to owner.
    info!("membera: sending device info to owner");
    let device_id = client.get_device_id().await?;
    let pk = client.get_key_bundle().await?;
    onboard
        .send(
            &DeviceInfo {
                name: env.membera.name.clone(),
                device_id,
                pk: pk.clone(),
            },
            env.owner.tcp_addr,
        )
        .await?;
    info!("membera: sent device info to owner");

    // Setup sync peers.
    let sync_cfg = SyncPeerConfig::builder().interval(SYNC_INTERVAL).build()?;
    info!("membera: adding operator sync peer");
    team.add_sync_peer(env.operator.sync_addr, sync_cfg.clone())
        .await
        .expect("expected to add sync peer");

    // wait for syncing.
    sleep(SLEEP_INTERVAL).await;

    // Wait for admin to create label.
    info!("membera: waiting for admin to create label");
    let queries = team.queries();
    let label1 = loop {
        if let Ok(labels) = queries.labels().await {
            if let Some(label1) = labels.iter().next() {
                break label1.id;
            }
        }
        sleep(SLEEP_INTERVAL).await;
    };

    // Loop until this device has the `Operator` role assigned to it.
    info!("membera: waiting for all devices to be added to team and operator role assignment");
    let queries = team.queries();
    'outer: loop {
        if let Ok(devices) = queries.devices_on_team().await {
            if devices.iter().count() == 5 {
                for device in devices.iter() {
                    if let Ok(Role::Operator) = queries.device_role(*device).await {
                        break 'outer;
                    }
                }
            }
        }
        sleep(3 * SLEEP_INTERVAL).await;
    }
    info!("membera: detected that all devices have been added to team and operator role has been assigned");

    // Send device info to operator.
    info!("membera: sending device info to operator");
    onboard
        .send(
            &DeviceInfo {
                name: env.membera.name,
                device_id,
                pk,
            },
            env.operator.tcp_addr,
        )
        .await?;
    info!("membera: sent device info to operator");

    // wait for syncing.
    sleep(SLEEP_INTERVAL).await;

    // Check that label has been assigned to membera and memberb.
    'outer: loop {
        if let Ok(devices) = queries.devices_on_team().await {
            let mut labels_assigned = 0;
            for device in devices.iter() {
                if let Ok(labels) = queries.device_label_assignments(*device).await {
                    if labels.iter().count() > 0 {
                        labels_assigned += 1;
                        if labels_assigned >= 2 {
                            break 'outer;
                        }
                    }
                }
            }
        }
        sleep(3 * SLEEP_INTERVAL).await;
    }

    // Remove operator sync peer.
    info!("membera: removing operator sync peer");
    team.remove_sync_peer(env.operator.sync_addr).await?;

    // Create a bidi AQC channel.
    info!("membera: creating bidi channel");
    let mut chan = client
        .aqc()
        .create_bidi_channel(
            team_info.team_id,
            NetIdentifier(
                env.memberb
                    .aqc_addr
                    .to_string()
                    .try_into()
                    .expect("addr is valid text"),
            ),
            label1,
        )
        .await
        .expect("expected to create bidi channel");

    // Create stream on bidi channel.
    info!("membera: creating bidi stream");
    let mut stream = chan
        .create_bidi_stream()
        .await
        .expect("expected to create bidi stream");

    // Send data.
    info!("membera: sending AQC data");
    let req = Bytes::from_static(b"hello");
    stream
        .send(req.clone())
        .await
        .expect("expected to send data");
    info!("membera: sent AQC data");

    // Receive data.
    info!("membera: receiving AQC data");
    let resp = stream.receive().await?.expect("expected to receive data");
    assert_eq!(req, resp);
    info!("membera: received AQC data");

    info!("membera: complete");

    Ok(())
}
