//! Multi-node Aranya example written in Rust.

use std::{
    env,
    path::Path,
    process::{Child, Command},
};

use anyhow::Result;
use aranya_example_multi_node::{env::EnvVars, tracing::init_tracing};
use tokio::task::JoinSet;
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

    // Start device for each team member.
    let mut set = JoinSet::new();
    for device in env.devices {
        info!("starting {} client", device.name);
        let mut child = client(&release, device.name.clone()).expect("expected to spawn client");
        set.spawn(async move {
            let _ = child.wait();
        });
    }
    // Wait for all client processes to complete.
    set.join_all().await;

    info!("completed aranya-example-multi-node example");

    Ok(())
}

// Spawn a client child process.
fn client(release: &Path, device: String) -> Result<Child> {
    let daemon_path = release.join("aranya-daemon");
    let child = Command::new(release.join(format!("aranya-example-multi-node-{:}", device)))
        .arg("--daemon-path")
        .arg(daemon_path)
        .spawn()?;
    Ok(child)
}
