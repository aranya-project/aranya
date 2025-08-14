//! Member B device.

use std::{path::PathBuf, time::Duration};

use anyhow::{bail, Result};
use aranya_client::{
    aqc::{AqcPeerChannel, AqcPeerStream},
    AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig,
};
use aranya_daemon_api::{Role, TeamId};
use aranya_example_multi_node::{
    age::AgeEncryptor,
    env::EnvVars,
    info::DeviceInfo,
    tcp::{TcpClient, TcpServer},
    tracing::init_tracing,
};
use backon::{ExponentialBuilder, Retryable};
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
    let server = TcpServer::bind(env.memberb.tcp_addr).await?;
    info!("memberb: started tcp server");

    // Initialize client.
    info!("memberb: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&args.uds_sock)
            .aqc_server_addr(&env.memberb.aqc_addr)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("memberb: initialized client");

    // Initialize `age` encryptor.
    let encryptor = AgeEncryptor::new(env.passphrase);

    // Get team ID from owner.
    let team_id: TeamId = postcard::from_bytes(&encryptor.decrypt(&server.recv().await?)?)?;
    info!("memberb: received team ID from owner");

    // Get seed IKM from owner.
    let seed_ikm = postcard::from_bytes(&encryptor.decrypt(&server.recv().await?)?)?;
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
    info!("memberb: sending device ID to owner");
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&encryptor.encrypt(&postcard::to_allocvec(&client.get_device_id().await?)?)?)
        .await?;
    info!("memberb: sent device ID to owner");

    // Send public keys to owner.
    info!("memberb: sending public keys to owner");
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&encryptor.encrypt(&postcard::to_allocvec(&client.get_key_bundle().await?)?)?)
        .await?;
    info!("memberb: sending public keys to owner");

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

    // Wait for admin to create label.
    info!("memberb: waiting for admin to create label");
    let queries = team.queries();
    loop {
        if let Ok(labels) = queries.labels().await {
            if labels.iter().next().is_some() {
                break;
            }
        }
        sleep(sleep_interval).await;
    }

    // Loop until this device has the `Operator` role assigned to it.
    info!("memberb: waiting for all devices to be added to team and operator role assignment");
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
        sleep(3 * sleep_interval).await;
    }
    info!("memberb: detected that all devices have been added to team and operator role has been assigned");

    // Send device info to operator.
    info!("memberb: sending device info to operator");
    TcpClient::connect(env.operator.tcp_addr)
        .await?
        .send(&encryptor.encrypt(&postcard::to_allocvec(&DeviceInfo {
            name: DEVICE_NAME.to_string(),
            device_id: client.get_device_id().await?,
        })?)?)
        .await?;
    info!("memberb: sent device info to operator");

    // wait for syncing.
    sleep(sleep_interval).await;

    // Check that label has been assigned to membera and memberb.
    let queries = team.queries();
    'outer: loop {
        if let Ok(devices) = queries.devices_on_team().await {
            let mut labels_assigned = 0;
            for device in devices.iter() {
                if let Ok(labels) = queries.device_label_assignments(*device).await {
                    labels_assigned += labels.iter().count();
                    if labels_assigned >= 2 {
                        break 'outer;
                    }
                }
            }
        }
        sleep(3 * sleep_interval).await;
    }

    // Remove operator sync peer.
    info!("memberb: removing operator sync peer");
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

    info!("memberb: complete");

    Ok(())
}
