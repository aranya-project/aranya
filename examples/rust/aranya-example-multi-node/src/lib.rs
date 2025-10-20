//! Aranya multi-node example lib.

pub mod age;
pub mod config;
pub mod env;
pub mod onboarding;
pub mod tcp;
pub mod tracing;

// TODO: hacky
pub async fn get_member_peer(
    client: &aranya_client::Client,
    team: aranya_client::TeamId,
) -> anyhow::Result<aranya_client::DeviceId> {
    let this_device = client.get_device_id().await?;
    let team = client.team(team);
    let queries = team.queries();
    let devices = queries.devices_on_team().await?;
    for &device in devices.iter() {
        if device.__id == this_device.__id {
            continue;
        }
        let role = queries.device_role(device).await?;
        if role == aranya_client::client::Role::Member {
            return Ok(device);
        }
    }
    Err(anyhow::anyhow!("peer not found"))
}
