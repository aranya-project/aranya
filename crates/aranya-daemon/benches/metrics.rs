use std::net::Ipv4Addr;

use anyhow::Result;
use aranya_daemon::{config::Config, Daemon};
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
    let addr_any = Addr::from((Ipv4Addr::LOCALHOST, 0));

    let cfg = Config {
        name: "daemon".into(),
        runtime_dir: work_dir.join("run"),
        state_dir: work_dir.join("state"),
        cache_dir: work_dir.join("cache"),
        logs_dir: work_dir.join("log"),
        config_dir: work_dir.join("config"),
        sync_addr: addr_any,
        afc: None,
        aqc: None,
    };

    let rt = Runtime::new()?;
    let _daemon = rt.block_on(Daemon::load(cfg))?;
    Ok(())
}
