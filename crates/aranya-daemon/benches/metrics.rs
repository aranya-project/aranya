use std::net::Ipv4Addr;

use anyhow::Result;
use aranya_daemon::{
    config::{AqcConfig, Config, QuicSyncConfig, SyncConfig, Toggle},
    Daemon,
};
use aranya_util::Addr;
use divan::AllocProfiler;
use tokio::runtime::Runtime;

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

// NOTE: divan currently requires sync functions to work, so we spawn a runtime and block on async.
#[divan::bench]
fn daemon_startup() -> Result<()> {
    let work_dir = tempfile::tempdir()?.path().to_path_buf();

    let cfg = Config {
        name: "daemon".into(),
        runtime_dir: work_dir.join("run"),
        state_dir: work_dir.join("state"),
        cache_dir: work_dir.join("cache"),
        logs_dir: work_dir.join("log"),
        config_dir: work_dir.join("config"),
        sync: SyncConfig {
            quic: Toggle::Enabled(QuicSyncConfig {
                addr: Addr::from((Ipv4Addr::UNSPECIFIED, 0)),
            }),
        },
        aqc: Toggle::Enabled(AqcConfig {}),
    };

    let rt = Runtime::new()?;
    let _daemon = rt.block_on(Daemon::load(cfg))?;
    Ok(())
}
