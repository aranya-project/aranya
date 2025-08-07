use std::{env, path::Path, process::Command};

use anyhow::Result;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<()> {
    println!("aranya-example-multi-node");

    let devices = ["owner", "admin", "operator", "membera", "memberb"];

    let binding = env::var("CARGO_WORKSPACE_DIR")?;
    let workspace = Path::new(&binding);
    println!("{:?}", workspace);
    let release = workspace.join("target").join("release");
    let mut set = JoinSet::new();
    for device in devices {
        let path = release.join(format!("aranya-example-multi-node-{:}", device));
        println!("cmd path: {:?}", path);
        let mut command = Command::new(path);
        set.spawn(async move {
            let output = command.output().expect("expected to run command");
            println!("{:?}", output);
        });
    }
    set.join_all().await;
    Ok(())
}
