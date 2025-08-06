use std::net::Ipv4Addr;

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
/// Benchmarks how long the daemon takes to set itself up to be spawned.
#[divan::bench]
fn daemon_startup() {
    let work_dir = tempfile::tempdir().unwrap().path().to_path_buf();
    let rt = Runtime::new().unwrap();

    let cfg = Config {
        name: "test-daemon-run".into(),
        runtime_dir: work_dir.join("run"),
        state_dir: work_dir.join("state"),
        cache_dir: work_dir.join("cache"),
        logs_dir: work_dir.join("logs"),
        config_dir: work_dir.join("config"),
        sync: SyncConfig {
            quic: Toggle::Enabled(QuicSyncConfig {
                addr: Addr::from((Ipv4Addr::LOCALHOST, 0)),
            }),
        },
        aqc: Toggle::Enabled(AqcConfig {}),
    };

    for dir in [
        &cfg.runtime_dir,
        &cfg.state_dir,
        &cfg.cache_dir,
        &cfg.logs_dir,
        &cfg.config_dir,
    ] {
        rt.block_on(aranya_util::create_dir_all(dir))
            .expect("should be able to create directory");
    }

    let _daemon = rt.block_on(Daemon::load(cfg)).unwrap();
}
