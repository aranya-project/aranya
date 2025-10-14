//! Multi-node Aranya example written in Rust.

use std::{
    env,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use aranya_example_multi_node::{config::create_config, env::EnvVars, tracing::init_tracing};
use tempfile::tempdir;
use tokio::{
    process::{Child, Command},
    task::JoinSet,
    time::sleep,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    info!("starting aranya-example-multi-node example");

    let mut args = env::args();
    args.next(); // skip executable name
                 // Get release directory from input args.
    let release = {
        let path = args.next().context("missing `release` path")?;
        PathBuf::from(path)
    };

    let workspace = {
        let path = args.next().context("missing `release` path")?;
        PathBuf::from(path)
    };

    // Generate environment file for deploying on different machines.
    let env = EnvVars::default();
    let example = workspace.join("example.env");
    env.generate(&example).await?;

    // Set environment variables before spawning child processes.
    env.set();

    // Start a daemon for each device.
    let tmp = tempdir()?;
    let mut daemons = Vec::with_capacity(env.devices().count());
    for device in env.devices() {
        // Generate config file.
        info!("generating daemon config file for {}", device.name);
        let cfg = create_config(device.name.clone(), device.sync_addr, tmp.path())
            .await
            .expect("expected to generate daemon config file");

        // Start daemon.
        info!("starting {} daemon", device.name);
        let child = daemon(&release, &cfg).expect("expected to spawn daemon");
        daemons.push(child);
    }
    // Wait for daemons to start.
    sleep(Duration::from_secs(2)).await;

    // Start device for each team member.
    let mut processes = JoinSet::new();
    for device in env.devices() {
        info!("starting {} client", device.name);
        let uds_sock = tmp
            .path()
            .join(device.name.clone())
            .join("daemon")
            .join("run")
            .join("uds.sock");

        let mut child =
            client(device.name.clone(), &uds_sock, &release).expect("expected to spawn client");
        // Spawn device process and collect exit status.
        processes.spawn(async move {
            let status = child.wait().await.unwrap();
            assert!(status.success(), "{status:?}");
        });
    }
    // Wait for all device processes to complete.
    processes.join_all().await;
    // Kill daemon processes.
    for mut d in daemons {
        let _ = d.kill().await;
    }

    info!("completed aranya-example-multi-node example");

    Ok(())
}

// Spawn a daemon child process.
fn daemon(release: &Path, cfg: &Path) -> Result<Child> {
    let child = Command::new(release.join("aranya-daemon"))
        .kill_on_drop(true)
        .arg("--config")
        .arg(cfg)
        .spawn()?;
    Ok(child)
}

// Spawn a client child process.
fn client(device: String, uds_sock: &Path, release: &Path) -> Result<Child> {
    let child = Command::new(release.join(format!("aranya-example-multi-node-{:}", device)))
        .kill_on_drop(true)
        .arg("--uds-sock")
        .arg(uds_sock)
        .spawn()?;
    Ok(child)
}
