use anyhow::Result;
use aranya_example_multi_node::tracing::init_tracing;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!("starting aranya-example-multi-node-operator");
    Ok(())
}
