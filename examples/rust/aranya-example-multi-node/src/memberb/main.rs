//! Member B device.

use std::{path::PathBuf, time::Duration};

use anyhow::{bail, Result};
use aranya_client::{
    aqc::{AqcPeerChannel, AqcPeerStream},
    AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig,
};
use aranya_daemon_api::TeamId;
use aranya_example_multi_node::{
    env::EnvVars,
    info::DeviceInfo,
    tcp::{TcpClient, TcpServer},
    tracing::init_tracing,
};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use tokio::time::sleep;
use tracing::info;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Daemon UDS socket path.
    #[arg(long)]
    uds_sock: PathBuf,
    /// AQC server address.
    #[arg(long)]
    aqc_addr: Addr,
    /// TCP server address for receiving team info from owner.
    #[arg(long)]
    tcp_addr: Addr,
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

    // Start TCP server.
    info!("memberb: starting tcp server");
    let server = TcpServer::bind(args.tcp_addr).await?;
    info!("memberb: started tcp server");

    // Initialize client.
    info!("memberb: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&args.uds_sock)
            .aqc_server_addr(&args.aqc_addr)
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
    let team = client.add_team(add_team_cfg.clone()).await?;
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
    for device in &env.devices {
        if device.name == DEVICE_NAME {
            continue;
        }
        info!("memberb: adding sync peer {}", device.name);
        team.add_sync_peer(device.sync_addr, sync_cfg.clone())
            .await?;
    }

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

    // Receive bidi channel.
    info!("memberb: receiving AQC bidi channel");
    let AqcPeerChannel::Bidi(mut chan) = client.aqc().receive_channel().await? else {
        bail!("expected a bidirectional channel");
    };
    info!("memberb: received AQC bidi channel");

    // Receive bidi steam.
    let AqcPeerStream::Bidi(mut stream) = chan.receive_stream().await? else {
        bail!("expected a bidirectional stream");
    };
    info!("memberb: received bidi stream");

    // Receive data.
    let data = stream.receive().await?.expect("expected to receive data");
    info!("memberb: received AQC data");

    // Send data.
    stream.send(data).await?;
    info!("memberb: sent AQC data");

    // wait for membera to receive the data before closing the stream.
    sleep(sleep_interval).await;

    info!("memberb: complete");

    Ok(())
}
