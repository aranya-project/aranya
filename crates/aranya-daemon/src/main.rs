//! Daemon entrypoint.

#![allow(unstable_name_collisions)]
#![deny(clippy::wildcard_imports, missing_docs)]

use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
    process,
};

use anyhow::{Context, Result};
use aranya_daemon::{config::Config, Daemon};
use aranya_util::error::ReportExt as _;
use clap::Parser;
use tokio::runtime::Runtime;
use tracing::{error, info};
use tracing_subscriber::{prelude::*, EnvFilter};

fn main() -> Result<()> {
    let flags = Args::parse();

    let cfg = Config::load(&flags.config)?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(io::stderr)
                .with_file(false)
                .compact()
                .with_filter(EnvFilter::from_env("ARANYA_DAEMON")),
        )
        .init();

    info!("starting Aranya daemon");

    let pid = PidFile::create(cfg.pid_path()).context("unable to create PID file")?;
    info!(name = cfg.name, "wrote PID file to {pid}");

    let rt = Runtime::new()?;
    rt.block_on(async {
        let daemon = Daemon::load(cfg).await.context("unable to load daemon")?;
        info!("loaded Aranya daemon");

        daemon.spawn().join().await?;

        Ok(())
    })
    .inspect_err(|err| error!(error = ?err))
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the configuration file.
    #[arg(long)]
    config: PathBuf,
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
    fn create<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        fs::write(path.as_ref(), process::id().to_string())?;
        Ok(Self {
            path: path.as_ref().to_owned(),
        })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            error!(error = %err.report(), "unable to remove PID file")
        }
    }
}

impl fmt::Display for PidFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.path.display())
    }
}
