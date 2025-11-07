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

    let shm = format!("/shm_{}", device);
    let _ = rustix::shm::unlink(&shm);
    // TODO: reuse code to derive subdirectories for all examples.
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

                [afc]
                enable = true
                shm_path = {shm:?}
                max_chans = 100

                [sync.quic]
                enable = true
                addr = {sync_addr:?}
                "#
    );
    print_neatly(&buf);
    fs::write(&cfg, buf).await?;
    info!("generated config file: {:?}", cfg);

    Ok(cfg)
}

fn print_neatly(data: &str) {
    info!("\tconfig:{{");
    // 1. Split the string into an iterator of lines.
    data.lines()
        // 2. Trim leading and trailing whitespace from each line.
        .map(|line| line.trim())
        // 3. Filter out any lines that become entirely empty after trimming (like the initial '\n' or empty lines).
        .filter(|line| !line.is_empty())
        // 4. Iterate over the cleaned lines and print them.
        .for_each(|line| info!("\t{}", line));
    info!("}}");
}
