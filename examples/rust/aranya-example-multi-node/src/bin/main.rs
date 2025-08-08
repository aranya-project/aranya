//! Multi-node Aranya example written in Rust.

use std::{
    env,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Child, Command},
};

use anyhow::{Context as _, Result};
use aranya_example_multi_node::tracing::init_tracing;
use aranya_util::Addr;
use tempfile::tempdir;
use tokio::{fs, task::JoinSet};
use tracing::info;

/// An Aranya device.
struct Device {
    /// Human-readable name of the Aranya device.
    name: String,
    /// Address to host AQC server at.
    aqc_addr: Addr,
    /// Address to host TCP server at.
    tcp_addr: Addr,
    /// Address to host QUIC sync server at.
    sync_addr: Addr,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    info!("starting aranya-example-multi-node example");

    let tmp = tempdir()?;
    // TODO: load this info from config or env file that can be copied onto other machines.
    let devices = [
        Device {
            name: "owner".into(),
            aqc_addr: Addr::from((Ipv4Addr::LOCALHOST, 10001)),
            tcp_addr: Addr::from((Ipv4Addr::LOCALHOST, 10002)),
            sync_addr: Addr::from((Ipv4Addr::LOCALHOST, 10003)),
        },
        Device {
            name: "admin".into(),
            aqc_addr: Addr::from((Ipv4Addr::LOCALHOST, 10004)),
            tcp_addr: Addr::from((Ipv4Addr::LOCALHOST, 10005)),
            sync_addr: Addr::from((Ipv4Addr::LOCALHOST, 10006)),
        },
        Device {
            name: "operator".into(),
            aqc_addr: Addr::from((Ipv4Addr::LOCALHOST, 10007)),
            tcp_addr: Addr::from((Ipv4Addr::LOCALHOST, 10008)),
            sync_addr: Addr::from((Ipv4Addr::LOCALHOST, 10009)),
        },
        Device {
            name: "membera".into(),
            aqc_addr: Addr::from((Ipv4Addr::LOCALHOST, 10010)),
            tcp_addr: Addr::from((Ipv4Addr::LOCALHOST, 10011)),
            sync_addr: Addr::from((Ipv4Addr::LOCALHOST, 10012)),
        },
        Device {
            name: "memberb".into(),
            aqc_addr: Addr::from((Ipv4Addr::LOCALHOST, 10013)),
            tcp_addr: Addr::from((Ipv4Addr::LOCALHOST, 10014)),
            sync_addr: Addr::from((Ipv4Addr::LOCALHOST, 10015)),
        },
    ];

    // Set environment variables before spawning child processes.
    set_env_vars(&devices);

    let env = env::var("CARGO_WORKSPACE_DIR")
        .expect("expected CARGO_WORKSPACE_DIR env var to be defined");
    let workspace = Path::new(&env);
    let release = workspace.join("target").join("release");

    // Start a daemon for each device.
    let mut handles = Vec::new();
    for device in &devices {
        // Generate config file.
        info!("generating daemon config file for {}", device.name);
        let cfg = create_config(device.name.clone(), device.sync_addr, tmp.path().into())
            .await
            .expect("expected to generate daemon config file");

        // Start daemon.
        info!("starting {} daemon", device.name);
        let child = daemon(&release, &cfg).expect("expected to spawn daemon");
        handles.push(child);
    }

    // Start device for each team member.
    let mut set = JoinSet::new();
    for device in &devices {
        info!("starting {} client", device.name);
        let uds_sock = tmp
            .path()
            .join(device.name.clone())
            .join("daemon")
            .join("run")
            .join("uds.sock");
        let mut child = client(
            &release,
            device.name.clone(),
            &uds_sock,
            device.aqc_addr,
            device.tcp_addr,
        )
        .expect("expected to spawn client");
        set.spawn(async move {
            let _ = child.wait();
        });
    }
    set.join_all().await;
    for mut handle in handles {
        let _ = handle.kill();
    }

    info!("completed aranya-example-multi-node example");

    Ok(())
}

// Set environment variables for child processes.
fn set_env_vars(devices: &[Device]) {
    env::set_var("ARANYA_EXAMPLE", "info");
    for device in devices {
        env::set_var(
            format!("ARANYA_AQC_ADDR_{}", device.name.to_uppercase()),
            device.aqc_addr.to_string(),
        );
        env::set_var(
            format!("ARANYA_TCP_ADDR_{}", device.name.to_uppercase()),
            device.tcp_addr.to_string(),
        );
        env::set_var(
            format!("ARANYA_SYNC_ADDR_{}", device.name.to_uppercase()),
            device.sync_addr.to_string(),
        );
    }
}

// Create a daemon config file.
async fn create_config(device: String, sync_addr: Addr, dir: PathBuf) -> Result<PathBuf> {
    let device_dir = dir.join(&device);
    let work_dir = device_dir.join("daemon");
    fs::create_dir_all(&work_dir).await?;

    let cfg = work_dir.join("config.toml");

    let runtime_dir = work_dir.join("run");
    let state_dir = work_dir.join("state");
    let cache_dir = work_dir.join("cache");
    let logs_dir = work_dir.join("logs");
    let config_dir = work_dir.join("config");
    let sync_addr = sync_addr.to_string();
    for dir in &[&runtime_dir, &state_dir, &cache_dir, &logs_dir, &config_dir] {
        fs::create_dir_all(dir)
            .await
            .with_context(|| format!("unable to create directory: {}", dir.display()))?;
    }

    let buf = format!(
        r#"
                name = {device:?}
                runtime_dir = {runtime_dir:?}
                state_dir = {state_dir:?}
                cache_dir = {cache_dir:?}
                logs_dir = {logs_dir:?}
                config_dir = {config_dir:?}

                aqc.enable = true

                [sync.quic]
                enable = true
                addr = {sync_addr:?}
                "#
    );
    fs::write(&cfg, buf).await?;
    info!("generated config file: {:?}", cfg);

    Ok(cfg)
}

// Spawn a daemon child process.
fn daemon(release: &Path, cfg: &Path) -> Result<Child> {
    let child = Command::new(release.join("aranya-daemon"))
        .arg("--config")
        .arg(cfg)
        .spawn()?;
    Ok(child)
}

// Spawn a client child process.
fn client(
    release: &Path,
    device: String,
    uds_sock: &Path,
    aqc_addr: Addr,
    tcp_addr: Addr,
) -> Result<Child> {
    let child = Command::new(release.join(format!("aranya-example-multi-node-{:}", device)))
        .arg("--uds-sock")
        .arg(uds_sock)
        .arg("--aqc-addr")
        .arg(aqc_addr.to_string())
        .arg("--tcp-addr")
        .arg(tcp_addr.to_string())
        .spawn()?;
    Ok(child)
}
