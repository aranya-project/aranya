//! Member B device.

use std::{path::PathBuf, time::Duration};

use anyhow::{bail, Result};
use aranya_client::{
    aqc::{AqcPeerChannel, AqcPeerStream},
    AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig,
};
use aranya_daemon_api::TeamId;
use aranya_example_multi_node::{
    config::create_config,
    env::EnvVars,
    info::DeviceInfo,
    tcp::{TcpClient, TcpServer},
    tracing::init_tracing,
};
use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use tempfile::tempdir;
use tokio::{process::Command, time::sleep};
use tracing::info;

/// CLI args.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Daemon executable path.
    #[arg(long)]
    daemon_path: PathBuf,
}

/// Name of the current Aranya device.
const DEVICE_NAME: &str = "memberb";

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!("starting aranya-example-multi-node-memberb");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;
    // Generate daemon config file.
    let tmp = tempdir()?;
    info!("memberb: generating daemon config");
    let cfg = create_config(
        DEVICE_NAME.to_string(),
        env.memberb.sync_addr,
        tmp.path().into(),
    )
    .await
    .expect("expected to generate daemon config file");

    // Start daemon.
    info!("memberb: starting daemon");
    let _child = Command::new(args.daemon_path)
        .kill_on_drop(true)
        .arg("--config")
        .arg(cfg)
        .spawn()?;
    let uds_sock = tmp
        .path()
        .join(DEVICE_NAME)
        .join("daemon")
        .join("run")
        .join("uds.sock");
    // Wait for daemon to start.
    sleep(Duration::from_secs(2)).await;
    info!("memberb: started daemon");

    // Start TCP server.
    info!("memberb: starting tcp server");
    let server = TcpServer::bind(env.memberb.tcp_addr).await?;
    info!("memberb: started tcp server");

    // Initialize client.
    info!("memberb: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&uds_sock)
            .aqc_server_addr(&env.memberb.aqc_addr)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("memberb: initialized client");

    // Get team ID from owner.
    let team_id: TeamId = postcard::from_bytes(&server.recv().await?)?;
    info!("memberb: received team ID from owner");

    // Get seed IKM from owner.
    let seed_ikm = postcard::from_bytes(&server.recv().await?)?;
    info!("memberb: received seed ikm from owner");

    // Add team.
    let add_team_cfg = {
        let qs_cfg = AddTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        AddTeamConfig::builder()
            .quic_sync(qs_cfg)
            .team_id(team_id)
            .build()?
    };
    let team = client
        .add_team(add_team_cfg.clone())
        .await
        .expect("expected to add team");
    info!("memberb: added team");

    // Send device ID to owner.
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&postcard::to_allocvec(&client.get_device_id().await?)?)
        .await?;

    // Send public keys to owner.
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&postcard::to_allocvec(&client.get_key_bundle().await?)?)
        .await?;

    // Setup sync peers.
    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;
    info!("memberb: adding operator sync peer");
    team.add_sync_peer(env.operator.sync_addr, sync_cfg.clone())
        .await
        .expect("expected to add sync peer");

    // wait for syncing.
    sleep(sleep_interval).await;

    // Send device info to operator.
    TcpClient::connect(env.operator.tcp_addr)
        .await?
        .send(&postcard::to_allocvec(&DeviceInfo {
            name: DEVICE_NAME.to_string(),
            device_id: client.get_device_id().await?,
        })?)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // Remove operator sync peer.
    team.remove_sync_peer(env.operator.sync_addr).await?;

    // Receive bidi channel.
    info!("memberb: receiving AQC bidi channel");
    let AqcPeerChannel::Bidi(mut chan) = client
        .aqc()
        .receive_channel()
        .await
        .expect("expected to receive channel")
    else {
        bail!("expected a bidirectional channel");
    };
    info!("memberb: received AQC bidi channel");

    // Receive bidi steam.
    let AqcPeerStream::Bidi(mut stream) = chan
        .receive_stream()
        .await
        .expect("expected to receive stream")
    else {
        bail!("expected a bidirectional stream");
    };
    info!("memberb: received bidi stream");

    // Receive data.
    let data = stream.receive().await?.expect("expected to receive data");
    info!("memberb: received AQC data");

    // Send data.
    stream.send(data).await.expect("expected to send data");
    info!("memberb: sent AQC data");

    // wait for membera to receive the data before closing the stream.
    sleep(sleep_interval).await;

    info!("memberb: complete");

    Ok(())
}
