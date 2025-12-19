//! Aranya onboarding example lib.

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
    let devices = team.devices().await?;
    for &device in devices.iter() {
        if device == this_device {
            continue;
        }
        let role = team
            .device(device)
            .role()
            .await?
            .ok_or_else(|| anyhow::anyhow!("no role"))?;
        if role.name == "member" && role.default {
            return Ok(device);
        }
    }
    Err(anyhow::anyhow!("peer not found"))
}
