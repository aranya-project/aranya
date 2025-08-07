use std::{
    env, future,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context as _, Result};
use tempfile::tempdir;
use tokio::{
    fs,
    task::{self, JoinSet},
};
use tracing::{info, Metadata};
use tracing_subscriber::{
    layer::{Context, Filter},
    prelude::*,
    EnvFilter,
};

struct DemoFilter {
    env_filter: EnvFilter,
}

impl<S> Filter<S> for DemoFilter {
    fn enabled(&self, metadata: &Metadata<'_>, context: &Context<'_, S>) -> bool {
        if metadata.target().starts_with(module_path!()) {
            true
        } else {
            self.env_filter.enabled(metadata, context.clone())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    info!("starting aranya-example-multi-node");

    let tmp = tempdir()?;
    let devices = ["owner", "admin", "operator", "membera", "memberb"];

    let env = env::var("CARGO_WORKSPACE_DIR")
        .expect("expected CARGO_WORKSPACE_DIR env var to be defined");
    let workspace = Path::new(&env);
    let release = workspace.join("target").join("release");

    // Start a daemon for each device.
    for device in devices {
        // Generate config file.
        info!("generating daemon config file for {}", device);
        let cfg = create_config(device.into(), tmp.path().into()).await?;

        // Start daemon.
        info!("starting {} daemon", device);
        let mut daemon = daemon(&release);
        task::spawn(async move {
            let output = daemon
                .arg("--config")
                .arg(cfg)
                .output()
                .expect("expected to spawn aranya daemon");
            info!("{:?}", output);
        });
    }

    // Start device for each team member.
    let mut set = JoinSet::new();
    for device in devices {
        info!("starting {} client", device);
        let mut client = client(device.into(), &release);
        set.spawn(async move {
            let output = client.output().expect("expected to spawn aranya client");
            info!("{:?}", output);
        });
    }
    set.join_all().await;

    // TODO: rm
    future::pending().await
}

// Create a daemon config file.
async fn create_config(device: String, dir: PathBuf) -> Result<PathBuf> {
    let device_dir = dir.join(&device);
    let work_dir = device_dir.join("daemon");
    fs::create_dir_all(&work_dir).await?;

    let cfg = work_dir.join("config.toml");

    let runtime_dir = work_dir.join("run");
    let state_dir = work_dir.join("state");
    let cache_dir = work_dir.join("cache");
    let logs_dir = work_dir.join("logs");
    let config_dir = work_dir.join("config");
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
                addr = "127.0.0.1:0"
                "#
    );
    fs::write(&cfg, buf).await?;

    Ok(cfg)
}

// Initialize tracing.
fn init_tracing() {
    let filter = DemoFilter {
        env_filter: EnvFilter::try_from_env("ARANYA_EXAMPLE")
            .unwrap_or_else(|_| EnvFilter::new("off")),
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_file(false)
                .with_target(false)
                .compact()
                .with_filter(filter),
        )
        .init();
}

// Return a daemon command to run.
fn daemon(release: &Path) -> Command {
    Command::new(release.join("aranya-daemon"))
}

// Return a client command to run.
fn client(device: String, release: &Path) -> Command {
    Command::new(release.join(format!("aranya-example-multi-node-{:}", device)))
}
