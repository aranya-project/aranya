use std::{thread::sleep, time::Duration};

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

// NOTE: We currently have to have a synchronous functions for divan to work correctly, so we spawn
// a runtime and block on all async calls.
#[divan::bench]
fn daemon_startup() -> Result<()> {
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let cfg = Config {
        name: "daemon".into(),
        work_dir: work_dir.clone(),
        uds_api_path: work_dir.join("uds.sock"),
        pid_file: work_dir.join("pid"),
        sync_addr: Addr::new("localhost", 0)?,
        afc: None,
        aqc: None,
    };

    let rt = Runtime::new()?;
    let daemon = rt.block_on(Daemon::load(cfg))?;
    let handle = rt.spawn(daemon.run()).abort_handle();
    sleep(Duration::from_millis(1));
    handle.abort();

    Ok(())
}
