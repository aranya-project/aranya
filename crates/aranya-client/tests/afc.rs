#![allow(clippy::arithmetic_side_effects, clippy::panic)]
#[cfg(feature = "afc")]
mod common;

#[cfg(feature = "afc")]
use {
    crate::common::{sleep, DevicesCtx, SLEEP_INTERVAL},
    anyhow::{Context, Result},
    aranya_client::afc::Channels,
    aranya_client::client::ChanOp,
    aranya_daemon_api::text,
};

/// Demonstrate assigning/revoking a label requires `CanUseAfc` permission.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_create_assign_revoke_delete_label() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_create_assign_revoke_delete_label").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // create default roles
    let default_roles = devices.setup_default_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices
        .add_all_device_roles(team_id, &default_roles)
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?;
    let owner_team = devices.owner.client.team(team_id);
    let membera_team = devices.membera.client.team(team_id);
    let memberb_team = devices.memberb.client.team(team_id);

    // Query team labels to show label has not been created yet.
    membera_team.sync_now(owner_addr, None).await?;
    assert_eq!(membera_team.labels().await?.iter().count(), 0);
    memberb_team.sync_now(owner_addr, None).await?;
    assert_eq!(memberb_team.labels().await?.iter().count(), 0);

    let label_id = owner_team
        .create_label(text!("label1"), default_roles.owner().id)
        .await?;
    let op = ChanOp::SendRecv;

    // Query team labels to confirm the label was created.
    membera_team.sync_now(owner_addr, None).await?;
    assert_eq!(membera_team.labels().await?.iter().count(), 1);
    memberb_team.sync_now(owner_addr, None).await?;
    assert_eq!(memberb_team.labels().await?.iter().count(), 1);

    // Assigning labels to devices with the "operator" role should fail since it does not have `CanUseAfc` permission.
    owner_team
        .device(devices.operator.id)
        .assign_label(label_id, op)
        .await
        .context("unable to assign label")
        .expect_err("expected label assignment to fail");

    // Assigning labels to devices with the "member" role should succeed since the role has `CanUseAfc` permission.
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id, op)
        .await?;

    // Query team labels to confirm they have been assigned to devices.
    membera_team.sync_now(owner_addr, None).await?;
    assert_eq!(
        membera_team
            .device(devices.membera.id)
            .label_assignments()
            .await?
            .iter()
            .count(),
        1
    );
    memberb_team.sync_now(owner_addr, None).await?;
    assert_eq!(
        memberb_team
            .device(devices.memberb.id)
            .label_assignments()
            .await?
            .iter()
            .count(),
        1
    );

    // Revoke the labels.
    owner_team
        .device(devices.membera.id)
        .revoke_label(label_id)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .revoke_label(label_id)
        .await?;

    // Query team labels to confirm they have been revoked from devices.
    membera_team.sync_now(owner_addr, None).await?;
    assert_eq!(
        membera_team
            .device(devices.membera.id)
            .label_assignments()
            .await?
            .iter()
            .count(),
        0
    );
    memberb_team.sync_now(owner_addr, None).await?;
    assert_eq!(
        memberb_team
            .device(devices.memberb.id)
            .label_assignments()
            .await?
            .iter()
            .count(),
        0
    );

    // Delete the label.
    owner_team.delete_label(label_id).await?;

    // Query team labels to confirm the label has been deleted.
    membera_team.sync_now(owner_addr, None).await?;
    assert_eq!(membera_team.labels().await?.iter().count(), 0);
    memberb_team.sync_now(owner_addr, None).await?;
    assert_eq!(memberb_team.labels().await?.iter().count(), 0);

    // Verify deleted label can not be assigned to a device.
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await
        .expect_err("expected label assignment to fail with deleted label");

    Ok(())
}

/// Demonstrate creating a unidirectional AFC channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_create() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_create").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // create default roles
    let default_roles = devices.setup_default_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices
        .add_all_device_roles(team_id, &default_roles)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let label_id = owner_team
        .create_label(text!("label1"), default_roles.owner().id)
        .await?;
    let op = ChanOp::SendRecv;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id, op)
        .await?;

    // wait for syncing.
    let owner_addr = devices.owner.aranya_local_addr().await?;
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    // Create uni channel.
    let (_chan, ctrl) = devices
        .membera
        .client
        .afc()
        .create_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    devices
        .memberb
        .client
        .afc()
        .accept_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?;

    Ok(())
}

/// Demonstrate seal/open with unidirectional AFC send channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_send_chan_seal_open() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_send_chan_seal_open").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // create default roles
    let default_roles = devices.setup_default_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices
        .add_all_device_roles(team_id, &default_roles)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let label_id = owner_team
        .create_label(text!("label1"), default_roles.owner().id)
        .await?;
    let op = ChanOp::SendRecv;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id, op)
        .await?;

    // wait for syncing.
    let owner_addr = devices.owner.aranya_local_addr().await?;
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create uni channel.
    let (mut chan, ctrl) = membera_afc
        .create_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let recv = memberb_afc
        .accept_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?;

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + Channels::OVERHEAD];
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - Channels::OVERHEAD];
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")?;

    assert_eq!(afc_msg, plaintext);

    Ok(())
}

/// Demonstrate deleting a unidirectional AFC channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_delete() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_delete").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // create default roles
    let default_roles = devices.setup_default_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices
        .add_all_device_roles(team_id, &default_roles)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let label_id = owner_team
        .create_label(text!("label1"), default_roles.owner().id)
        .await?;
    let op = ChanOp::SendRecv;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id, op)
        .await?;

    // wait for syncing.
    let owner_addr = devices.owner.aranya_local_addr().await?;
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create uni channel.
    let (mut chan, ctrl) = membera_afc
        .create_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let recv = memberb_afc
        .accept_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?;

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + Channels::OVERHEAD];
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - Channels::OVERHEAD];
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")?;

    // Delete channel.
    chan.delete().await.context("unable to delete channel")?;
    recv.delete().await.context("unable to delete channel")?;

    // Try open/seal after delete.
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")
        .expect_err("expected seal to fail");
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")
        .expect_err("expected open to fail");

    Ok(())
}

/// Demonstrate revoking a label from devices deletes the channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_revoke_label() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_revoke_label").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;
    let default_roles = devices.setup_default_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices
        .add_all_device_roles(team_id, &default_roles)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let label_id = owner_team
        .create_label(text!("label1"), default_roles.owner().id)
        .await?;
    let op = ChanOp::SendRecv;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id, op)
        .await?;

    // wait for syncing.
    let owner_addr = devices.owner.aranya_local_addr().await?;
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create uni channel.
    let (mut chan, ctrl) = membera_afc
        .create_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let recv = memberb_afc
        .accept_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?;

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + Channels::OVERHEAD];
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - Channels::OVERHEAD];
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")?;

    // Revoke label from member devices.
    owner_team
        .device(devices.membera.id)
        .revoke_label(label_id)
        .await?;

    // wait for syncing.
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    // Wait for channel to be deleted.
    sleep(SLEEP_INTERVAL).await;

    // Try open/seal after channels are deleted.
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")
        .expect_err("expected seal to fail");
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")
        .expect_err("expected open to fail");

    Ok(())
}

/// Demonstrate deleting a label deletes the channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_delete_label() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_delete_label").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;
    let default_roles = devices.setup_default_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices
        .add_all_device_roles(team_id, &default_roles)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let label_id = owner_team
        .create_label(text!("label1"), default_roles.owner().id)
        .await?;
    let op = ChanOp::SendRecv;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id, op)
        .await?;

    // wait for syncing.
    let owner_addr = devices.owner.aranya_local_addr().await?;
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create uni channel.
    let (mut chan, ctrl) = membera_afc
        .create_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let recv = memberb_afc
        .accept_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?;

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + Channels::OVERHEAD];
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - Channels::OVERHEAD];
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
    devices
        .admin
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    // Delete label.
    owner_team.delete_label(label_id).await?;

    // wait for syncing.
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    // Wait for channel to be deleted.
    sleep(SLEEP_INTERVAL).await;

    // Try open/seal after channels are deleted.
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")
        .expect_err("expected seal to fail");
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")
        .expect_err("expected open to fail");

    Ok(())
}

/// Demonstrate removing channel devices from the team deletes the AFC channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_remove_devices() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_remove_devices").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;
    let default_roles = devices.setup_default_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices
        .add_all_device_roles(team_id, &default_roles)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let label_id = owner_team
        .create_label(text!("label1"), default_roles.owner().id)
        .await?;
    let op = ChanOp::SendRecv;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id, op)
        .await?;

    // wait for syncing.
    let owner_addr = devices.owner.aranya_local_addr().await?;
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create uni channel.
    let (mut chan, ctrl) = membera_afc
        .create_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let recv = memberb_afc
        .accept_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?;

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + Channels::OVERHEAD];
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - Channels::OVERHEAD];
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
    devices
        .admin
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    // Remove channel devices from team.
    owner_team
        .device(devices.membera.id)
        .remove_from_team()
        .await?;
    owner_team
        .device(devices.memberb.id)
        .remove_from_team()
        .await?;

    // wait for syncing.
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    // Wait for channel to be deleted.
    sleep(SLEEP_INTERVAL).await;

    // Try open/seal after channels are deleted.
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")
        .expect_err("expected seal to fail");
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")
        .expect_err("expected open to fail");

    Ok(())
}

/// Demonstrate revoking the role from a device deletes the AFC channel.
/// Each device can only have one role assigned to it.
/// Therefore, revoking the role implicitly removes the `CanUseAfc` perm.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_revoke_role() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_revoke_role").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;
    let default_roles = devices.setup_default_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices
        .add_all_device_roles(team_id, &default_roles)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let label_id = owner_team
        .create_label(text!("label1"), default_roles.owner().id)
        .await?;
    let op = ChanOp::SendRecv;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id, op)
        .await?;

    // wait for syncing.
    let owner_addr = devices.owner.aranya_local_addr().await?;
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create uni channel.
    let (mut chan, ctrl) = membera_afc
        .create_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let recv = memberb_afc
        .accept_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?;

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + Channels::OVERHEAD];
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - Channels::OVERHEAD];
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
    devices
        .admin
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    // Revoke roles from channel devices.
    owner_team
        .device(devices.membera.id)
        .revoke_role(default_roles.member().id)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .revoke_role(default_roles.member().id)
        .await?;

    // wait for syncing.
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    // Wait for channel to be deleted.
    sleep(SLEEP_INTERVAL).await;

    // Try open/seal after channels are deleted.
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")
        .expect_err("expected seal to fail");
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")
        .expect_err("expected open to fail");

    Ok(())
}

/// Demonstrate changing device to a role without `CanUseAfc` perm deletes the AFC channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_change_role_without_perm() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_change_role_without_perm").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;
    let default_roles = devices.setup_default_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices
        .add_all_device_roles(team_id, &default_roles)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let label_id = owner_team
        .create_label(text!("label1"), default_roles.owner().id)
        .await?;
    let op = ChanOp::SendRecv;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id, op)
        .await?;

    // wait for syncing.
    let owner_addr = devices.owner.aranya_local_addr().await?;
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create uni channel.
    let (mut chan, ctrl) = membera_afc
        .create_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let recv = memberb_afc
        .accept_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?;

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + Channels::OVERHEAD];
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - Channels::OVERHEAD];
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
    devices
        .admin
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    // Assign roles without `CanUseAfc` permission.
    owner_team
        .device(devices.membera.id)
        .change_role(default_roles.member().id, default_roles.operator().id)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .change_role(default_roles.member().id, default_roles.operator().id)
        .await?;

    // wait for syncing.
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    // Wait for channel to be deleted.
    sleep(SLEEP_INTERVAL).await;

    // Try open/seal after channels are deleted.
    chan.seal(&mut ciphertext, afc_msg)
        .context("unable to seal afc message")
        .expect_err("expected seal to fail");
    recv.open(&mut plaintext, &ciphertext)
        .context("unable to open afc message")
        .expect_err("expected open to fail");

    Ok(())
}

/// Demonstrate open/seal with multiple unidirectional AFC channels.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_multi_send_chans() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_multi_chans").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // create default roles
    let default_roles = devices.setup_default_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices
        .add_all_device_roles(team_id, &default_roles)
        .await?;

    let owner_team = devices.owner.client.team(team_id);

    // First label.
    let op = ChanOp::SendRecv;
    let label_id1 = owner_team
        .create_label(text!("label1"), default_roles.owner().id)
        .await?;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id1, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id1, op)
        .await?;

    // Second label.
    let label_id2 = owner_team
        .create_label(text!("label2"), default_roles.owner().id)
        .await?;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id2, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id2, op)
        .await?;

    // wait for syncing.
    let owner_addr = devices.owner.aranya_local_addr().await?;
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create first channel.
    let (mut chan1, ctrl1) = membera_afc
        .create_channel(team_id, devices.memberb.id, label_id1)
        .await
        .context("unable to create afc uni channel")?;

    // Create second channel.
    let (mut chan2, ctrl2) = memberb_afc
        .create_channel(team_id, devices.membera.id, label_id2)
        .await
        .context("unable to create afc uni channel")?;

    // Receive first channel.
    let recv1 = memberb_afc
        .accept_channel(team_id, ctrl1)
        .await
        .context("unable to receive afc uni channel")?;

    // Receive second channel.
    let recv2 = membera_afc
        .accept_channel(team_id, ctrl2)
        .await
        .context("unable to receive afc uni channel")?;

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext1 = vec![0u8; afc_msg.len() + Channels::OVERHEAD];
    chan1
        .seal(&mut ciphertext1, afc_msg)
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext1 = vec![0u8; ciphertext1.len() - Channels::OVERHEAD];
    recv1
        .open(&mut plaintext1, &ciphertext1)
        .context("unable to open afc message")?;
    assert_eq!(afc_msg, plaintext1);

    // Seal data.
    let mut ciphertext2 = vec![0u8; afc_msg.len() + Channels::OVERHEAD];
    chan2
        .seal(&mut ciphertext2, afc_msg)
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext2 = vec![0u8; ciphertext2.len() - Channels::OVERHEAD];
    recv2
        .open(&mut plaintext2, &ciphertext2)
        .context("unable to open afc message")?;
    assert_eq!(afc_msg, plaintext2);

    // Delete channels.
    chan1.delete().await.context("unable to delete channel")?;
    recv1.delete().await.context("unable to delete channel")?;

    chan2.delete().await.context("unable to delete channel")?;
    recv2.delete().await.context("unable to delete channel")?;

    // Try open/seal after delete.
    chan1
        .seal(&mut ciphertext1, afc_msg)
        .context("unable to seal afc message")
        .expect_err("expected seal to fail");
    recv1
        .open(&mut plaintext1, &ciphertext1)
        .context("unable to open afc message")
        .expect_err("expected open to fail");

    chan2
        .seal(&mut ciphertext2, afc_msg)
        .context("unable to seal afc message")
        .expect_err("expected seal to fail");
    recv2
        .open(&mut plaintext2, &ciphertext2)
        .context("unable to open afc message")
        .expect_err("expected open to fail");

    Ok(())
}
