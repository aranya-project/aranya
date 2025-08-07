use std::{env, future, path::Path, process::Command};

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

    info!("starting aranya-example-multi-node");

    let tmp_dir = tempdir()?;
    let devices = ["owner", "admin", "operator", "membera", "memberb"];

    let env = env::var("CARGO_WORKSPACE_DIR")
        .expect("expected CARGO_WORKSPACE_DIR env var to be defined");
    let workspace = Path::new(&env);
    info!("{:?}", workspace);
    let release = workspace.join("target").join("release");

    // Start a daemon for each device.
    for device in devices {
        // Generate config file
        let device_dir = tmp_dir.path().join(device);
        let work_dir = device_dir.join("daemon");
        fs::create_dir_all(&work_dir).await?;

        let cfg_path = work_dir.join("config.toml");

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
        fs::write(&cfg_path, buf).await?;

        // Start daemon
        let daemon_path = release.join("aranya-daemon");
        info!("daemon cmd: {:?} --config {:?}", daemon_path, cfg_path);
        let mut cmd = Command::new(daemon_path);
        task::spawn(async move {
            let output = cmd
                .arg("--config")
                .arg(cfg_path)
                .output()
                .expect("expected to run command");
            info!("{:?}", output);
        });
    }

    // Start device for each team member.
    let mut set = JoinSet::new();
    for device in devices {
        let path = release.join(format!("aranya-example-multi-node-{:}", device));
        info!("device cmd: {:?}", path);
        let mut cmd = Command::new(path);
        set.spawn(async move {
            let output = cmd.output().expect("expected to run command");
            info!("{:?}", output);
        });
    }
    set.join_all().await;

    // TODO: rm
    future::pending().await
}
