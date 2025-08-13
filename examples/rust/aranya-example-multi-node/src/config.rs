//! Utility for generating a daemon config file.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use aranya_util::Addr;
use tokio::fs;
use tracing::info;

// Create a daemon config file.
pub async fn create_config(device: String, sync_addr: Addr, dir: &Path) -> Result<PathBuf> {
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
