//! Daemon entrypoint.

use std::path::PathBuf;

use clap::Parser;
use config::Config;

mod config;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Configuration file
    cfg: PathBuf,
}

fn main() {
    println!("Hello, world!");

    let args = Args::parse();
    let _cfg = Config::load(args.cfg);
}
