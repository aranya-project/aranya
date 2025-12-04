use std::net::Ipv4Addr;

use aranya_daemon::{
    config::{Config, QuicSyncConfig, SyncConfig, Toggle},
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
fn daemon_startup(bencher: divan::Bencher<'_, '_>) {
    bencher
        .with_inputs(|| {
            // Spawn a new dir that will live for one run, since we want to measure "cold boot" perf
            let tmp_dir = tempfile::tempdir().expect("We should be able to create directories");
            let rt = Runtime::new().expect("We need a tokio runtime");
            let work_dir = tmp_dir.path().to_path_buf();

            #[cfg(feature = "afc")]
            let shm_path = {
                let path = "/test_daemon_run\0"
                    .try_into()
                    .expect("should be able to parse AFC shared memory path");
                let _ = aranya_fast_channels::shm::unlink(&path);
                path
            };

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
                        client_addr: None,
                    }),
                },
                #[cfg(feature = "afc")]
                afc: Toggle::Enabled(aranya_daemon::config::AfcConfig {
                    shm_path,
                    max_chans: 100,
                }),
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

            (tmp_dir, rt, cfg)
        })
        .bench_values(|(tmp_dir, rt, cfg)| {
            let daemon = rt
                .block_on(Daemon::load(cfg))
                .expect("We should always be able to construct a daemon");

            (tmp_dir, rt, daemon)
        });
}
