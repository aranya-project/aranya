//! Daemon entrypoint.

use std::path::PathBuf;

use clap::Parser;
use daemon::config::Config;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Configuration file
    cfg: PathBuf,
}

fn main() {
    let args = Args::parse();
    let _cfg = Config::load(args.cfg);
}
