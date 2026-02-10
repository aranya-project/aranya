//! Owner device.

#![allow(clippy::panic)]

use std::path::PathBuf;

use anyhow::Result;
use aranya_client::{Client, CreateTeamConfig, CreateTeamQuicSyncConfig};
use aranya_example_multi_node::{
    env::EnvVars,
    onboarding::{DeviceInfo, Onboard, TeamInfo},
    tracing::init_tracing,
};
use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use tracing::info;

/// Name of the current Aranya device.
const DEVICE_NAME: &str = "owner";

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
    init_tracing(module_path!());
    info!("starting aranya-example-multi-node-owner");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Start TCP server.
    info!("owner: starting onboarding server");
    let onboard = Onboard::new(env.owner.tcp_addr, env.passphrase.clone()).await?;
    info!("owner: started onboarding server");

    // Initialize client.
    info!("owner: initializing client");
    let client = (|| {
        Client::builder()
            .with_daemon_uds_path(&args.uds_sock)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("owner: initialized client");

    // Create team.
    info!("owner: creating team");
    let seed_ikm = {
        let mut buf = [0; 32];
        client.rand(&mut buf).await;
        buf
    };
    let cfg = {
        let qs_cfg = CreateTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        CreateTeamConfig::builder().quic_sync(qs_cfg).build()?
    };
    let team = client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    let team_id = team.team_id();
    info!("owner: created team: {}", team_id);

    {
        let roles = team.roles().await.expect("could not query roles");
        let mut roles = roles.iter();
        let owner_role = roles.next().expect("missing role");
        if roles.next().is_some() {
            panic!("unexpected roles");
        }
        assert_eq!(owner_role.name, "owner");
        team.setup_default_roles_no_owner()
            .await
            .expect("could not set up default roles");
    }

    // Send team ID and IKM to each device except for itself.
    // Receive the device ID and public key bundle from each device.
    // Add each device to the team.
    // Assign the proper role to each device.
    for device in env.devices() {
        if device.name == DEVICE_NAME {
            continue;
        }

        // Send team ID to device.
        info!("owner: sending team info to {}", device.name);
        onboard
            .send(&TeamInfo { team_id, seed_ikm }, device.tcp_addr)
            .await?;
        info!("owner: sent team info to {}", device.name);

        // Receive device info from device.
        let info: DeviceInfo = onboard.recv().await?;
        info!("owner: received device ID from {}", device.name);

        team.add_device_with_rank(info.pk, None, aranya_client::Rank::new(100)).await?;
        info!("owner: added device to team {}", device.name);

        // We did not assign a role by default, so let's add one.
        info!(
            "owner: assigning role {:?} to device {}",
            device.role, device.name
        );
        let role = team
            .roles()
            .await?
            .iter()
            .find(|r| *r.name == *device.role)
            .ok_or_else(|| anyhow::anyhow!("role not found"))?
            .clone();
        team.device(info.device_id)
            .assign_role(role.id)
            .await
            .expect("expected to assign role");
        info!(
            "owner: assigned role {:?} to device {}",
            device.role, device.name
        );
    }

    info!("owner: complete");

    Ok(())
}
