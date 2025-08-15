//! Multi-node Aranya example written in Rust.

use std::{env, path::Path, time::Duration};

use anyhow::Result;
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

    // Generate default environment file.
    let workspace = env::var("CARGO_WORKSPACE_DIR")
        .expect("expected CARGO_WORKSPACE_DIR env var to be defined");
    let workspace = Path::new(&workspace);
    let release = workspace.join("target").join("release");

    // Generate environment file for deploying on different machines.
    let env = EnvVars::default();
    env.generate(
        &workspace
            .join("examples")
            .join("rust")
            .join("aranya-example-multi-node")
            .join("example.env"),
    )
    .await?;
    // Set environment variables before spawning child processes.
    env.set();

    // Start a daemon for each device.
    let tmp = tempdir()?;
    let mut children = vec![];
    for device in env.devices() {
        // Generate config file.
        info!("generating daemon config file for {}", device.name);
        let cfg = create_config(device.name.clone(), device.sync_addr, tmp.path())
            .await
            .expect("expected to generate daemon config file");

        // Start daemon.
        info!("starting {} daemon", device.name);
        let child = daemon(&release, &cfg).expect("expected to spawn daemon");
        children.push(child);
    }
    // Wait for daemons to start.
    sleep(Duration::from_secs(2)).await;

    // Start device for each team member.
    let mut set = JoinSet::new();
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
        if device.name == "membera" {
            set.spawn(async move {
                let _ = child.wait().await;
            });
        } else {
            children.push(child);
        }
    }
    // Wait for longest running processes to complete (in this case it's membera).
    // Other device processes will automatically be killed when dropped.
    set.join_all().await;
    // Kill remaining child processes.
    for mut child in children {
        let _ = child.kill().await;
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
