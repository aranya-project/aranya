//! Daemon entrypoint.

#![allow(unstable_name_collisions)]
#![deny(clippy::wildcard_imports, missing_docs)]

use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
    process,
};

use anyhow::{Context, Result};
use clap::Parser;
use daemon::{config::Config, Daemon};
use tokio::runtime::Runtime;
use tracing::{error, info};
use tracing_subscriber::{prelude::*, EnvFilter};

fn main() -> Result<()> {
    let flags = Args::parse();

    let cfg = Config::load(&flags.cfg)?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_file(false)
                .with_target(false)
                .compact()
                .with_filter(EnvFilter::from_env("ARANYA_DAEMON")),
        )
        .init();

    let pid = PidFile::create(&cfg.pid_file).context("unable to create PID file")?;
    info!(name = cfg.name, "wrote PID file to {pid}");

    let rt = Runtime::new()?;
    rt.block_on(async {
        let daemon = Daemon::load(cfg).await.context("unable to load daemon")?;
        info!("loaded daemon");
        daemon.run().await
    })
    .inspect_err(|err| error!(err = ?err))
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Configuration file
    cfg: PathBuf,
}

/// A PID file.
///
/// It's deleted when dropped.
struct PidFile {
    path: PathBuf,
}

impl PidFile {
    /// Creates a new PID file at `path`.
    ///
    /// It's deleted when dropped.
    pub fn create<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        fs::write(path.as_ref(), process::id().to_string())?;
        Ok(Self {
            path: path.as_ref().to_owned(),
        })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            error!("unable to remove PID file: {err}")
        }
    }
}

impl fmt::Display for PidFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.path.display())
    }
}