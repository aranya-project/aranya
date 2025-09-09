#![allow(clippy::panic)]

mod common;
use anyhow::{bail, Context, Result};
use aranya_client::afc::{AfcChannel, AfcChannels, AfcUniChannel, Channel, Open, Seal};
use aranya_daemon_api::{text, ChanOp};

use crate::common::DevicesCtx;

/// Demonstrate creating a bidirectional AFC channel.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_bidi_chan_create() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_bidi_chan_create").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    let (_chan, ctrl) = devices
        .membera
        .client
        .afc()?
        .create_bidi_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc bidi channel")?;

    devices
        .memberb
        .client
        .afc()?
        .receive_channel(team_id, ctrl)
        .await
        .context("unable to receive afc bidi channel")?;

    Ok(())
}

/// Demonstrate seal/open with bidirectional AFC channel.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_bidi_chan_seal_open() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_bidi_chan_seal_open").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc()?;
    let memberb_afc = devices.memberb.client.afc()?;
    let overhead = AfcChannels::overhead();

    // Create bidi channel.
    let (mut chan, ctrl) = membera_afc
        .create_bidi_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc bidi channel")?;

    // Receive bidi channel.
    let AfcChannel::Bidi(mut recv) = memberb_afc
        .receive_channel(team_id, ctrl)
        .await
        .context("unable to receive afc bidi channel")?
    else {
        bail!("expected a bidirectional receive channel");
    };

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + overhead];
    chan.seal(afc_msg, &mut ciphertext)
        .await
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - overhead];
    recv.open(&ciphertext, &mut plaintext)
        .await
        .context("unable to open afc message")?;

    Ok(())
}

/// Demonstrate deleting a bidirectional AFC channel.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_bidi_chan_delete() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_bidi_chan_delete").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc()?;
    let memberb_afc = devices.memberb.client.afc()?;
    let overhead = AfcChannels::overhead();

    // Create bidi channel.
    let (mut chan, ctrl) = membera_afc
        .create_bidi_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc bidi channel")?;

    // Receive bidi channel.
    let AfcChannel::Bidi(mut recv) = memberb_afc
        .receive_channel(team_id, ctrl)
        .await
        .context("unable to receive afc bidi channel")?
    else {
        bail!("expected a bidirectional receive channel");
    };

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + overhead];
    chan.seal(afc_msg, &mut ciphertext)
        .await
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - overhead];
    recv.open(&ciphertext, &mut plaintext)
        .await
        .context("unable to open afc message")?;

    // Delete channel.
    let membera_channel_id = chan.channel_id();
    membera_afc
        .delete_channel(membera_channel_id)
        .await
        .context("unable to delete channel")?;
    let memberb_channel_id = recv.channel_id();
    memberb_afc
        .delete_channel(memberb_channel_id)
        .await
        .context("unable to delete channel")?;

    Ok(())
}

/// Demonstrate open/seal with multiple bidirectional AFC channels.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_bidi_multi_chans() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_bidi_multi_chans").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    // First label.
    let label_id1 = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id1, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id1, op)
        .await?;

    // Second label.
    let label_id2 = operator_team.create_label(text!("label2")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id2, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id2, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc()?;
    let memberb_afc = devices.memberb.client.afc()?;
    let overhead = AfcChannels::overhead();

    // Create first bidi channel.
    let (mut chan1, ctrl1) = membera_afc
        .create_bidi_channel(team_id, devices.memberb.id, label_id1)
        .await
        .context("unable to create afc bidi channel")?;

    // Create second bidi channel.
    let (mut chan2, ctrl2) = memberb_afc
        .create_bidi_channel(team_id, devices.membera.id, label_id2)
        .await
        .context("unable to create afc bidi channel")?;

    // Receive first bidi channel.
    let AfcChannel::Bidi(mut recv1) = memberb_afc
        .receive_channel(team_id, ctrl1)
        .await
        .context("unable to receive afc bidi channel")?
    else {
        bail!("expected a bidirectional receive channel");
    };

    // Receive second bidi channel.
    let AfcChannel::Bidi(mut recv2) = membera_afc
        .receive_channel(team_id, ctrl2)
        .await
        .context("unable to receive afc bidi channel")?
    else {
        bail!("expected a bidirectional receive channel");
    };

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext1 = vec![0u8; afc_msg.len() + overhead];
    chan1
        .seal(afc_msg, &mut ciphertext1)
        .await
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext1 = vec![0u8; ciphertext1.len() - overhead];
    recv1
        .open(&ciphertext1, &mut plaintext1)
        .await
        .context("unable to open afc message")?;

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext2 = vec![0u8; afc_msg.len() + overhead];
    chan2
        .seal(afc_msg, &mut ciphertext2)
        .await
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext2 = vec![0u8; ciphertext2.len() - overhead];
    recv2
        .open(&ciphertext2, &mut plaintext2)
        .await
        .context("unable to open afc message")?;

    // Delete channels.
    let membera_channel_id = chan1.channel_id();
    membera_afc
        .delete_channel(membera_channel_id)
        .await
        .context("unable to delete channel")?;
    let memberb_channel_id = recv1.channel_id();
    memberb_afc
        .delete_channel(memberb_channel_id)
        .await
        .context("unable to delete channel")?;

    let membera_channel_id = chan2.channel_id();
    membera_afc
        .delete_channel(membera_channel_id)
        .await
        .context("unable to delete channel")?;
    let memberb_channel_id = recv2.channel_id();
    memberb_afc
        .delete_channel(memberb_channel_id)
        .await
        .context("unable to delete channel")?;

    Ok(())
}

/// Demonstrate creating a unidirectional AFC channel.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_create() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_create").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    // Create uni channel.
    let (_chan, ctrl) = devices
        .membera
        .client
        .afc()?
        .create_uni_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    devices
        .memberb
        .client
        .afc()?
        .receive_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?;

    Ok(())
}

/// Demonstrate seal/open with unidirectional AFC channel.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_seal_open() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_seal_open").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc()?;
    let memberb_afc = devices.memberb.client.afc()?;
    let overhead = AfcChannels::overhead();

    // Create uni channel.
    let (mut chan, ctrl) = membera_afc
        .create_uni_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let AfcChannel::Uni(AfcUniChannel::Receive(mut recv)) = memberb_afc
        .receive_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?
    else {
        bail!("expected a unidirectional receive channel");
    };

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + overhead];
    chan.seal(afc_msg, &mut ciphertext)
        .await
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - overhead];
    recv.open(&ciphertext, &mut plaintext)
        .await
        .context("unable to open afc message")?;

    Ok(())
}

/// Demonstrate deleting a unidirectional AFC channel.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_delete() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_delete").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc()?;
    let memberb_afc = devices.memberb.client.afc()?;
    let overhead = AfcChannels::overhead();

    // Create uni channel.
    let (mut chan, ctrl) = membera_afc
        .create_uni_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let AfcChannel::Uni(AfcUniChannel::Receive(mut recv)) = memberb_afc
        .receive_channel(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?
    else {
        bail!("expected a unidirectional receive channel");
    };

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + overhead];
    chan.seal(afc_msg, &mut ciphertext)
        .await
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext = vec![0u8; ciphertext.len() - overhead];
    recv.open(&ciphertext, &mut plaintext)
        .await
        .context("unable to open afc message")?;

    // Delete channel.
    let membera_channel_id = chan.channel_id();
    membera_afc
        .delete_channel(membera_channel_id)
        .await
        .context("unable to delete channel")?;
    let memberb_channel_id = recv.channel_id();
    memberb_afc
        .delete_channel(memberb_channel_id)
        .await
        .context("unable to delete channel")?;

    Ok(())
}

/// Demonstrate open/seal with multiple unidirectional AFC channels.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_multi_chans() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_multi_chans").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    // First label.
    let label_id1 = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id1, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id1, op)
        .await?;

    // Second label.
    let label_id2 = operator_team.create_label(text!("label2")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id2, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id2, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    let membera_afc = devices.membera.client.afc()?;
    let memberb_afc = devices.memberb.client.afc()?;
    let overhead = AfcChannels::overhead();

    // Create first bidi channel.
    let (mut chan1, ctrl1) = membera_afc
        .create_uni_channel(team_id, devices.memberb.id, label_id1)
        .await
        .context("unable to create afc uni channel")?;

    // Create second bidi channel.
    let (mut chan2, ctrl2) = memberb_afc
        .create_uni_channel(team_id, devices.membera.id, label_id2)
        .await
        .context("unable to create afc uni channel")?;

    // Receive first bidi channel.
    let AfcChannel::Uni(AfcUniChannel::Receive(mut recv1)) = memberb_afc
        .receive_channel(team_id, ctrl1)
        .await
        .context("unable to receive afc uni channel")?
    else {
        bail!("expected a unidirectional receive channel");
    };

    // Receive second bidi channel.
    let AfcChannel::Uni(AfcUniChannel::Receive(mut recv2)) = membera_afc
        .receive_channel(team_id, ctrl2)
        .await
        .context("unable to receive afc uni channel")?
    else {
        bail!("expected a unidirectional receive channel");
    };

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext1 = vec![0u8; afc_msg.len() + overhead];
    chan1
        .seal(afc_msg, &mut ciphertext1)
        .await
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext1 = vec![0u8; ciphertext1.len() - overhead];
    recv1
        .open(&ciphertext1, &mut plaintext1)
        .await
        .context("unable to open afc message")?;

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext2 = vec![0u8; afc_msg.len() + overhead];
    chan2
        .seal(afc_msg, &mut ciphertext2)
        .await
        .context("unable to seal afc message")?;

    // Open data.
    let mut plaintext2 = vec![0u8; ciphertext2.len() - overhead];
    recv2
        .open(&ciphertext2, &mut plaintext2)
        .await
        .context("unable to open afc message")?;

    // Delete channels.
    let membera_channel_id = chan1.channel_id();
    membera_afc
        .delete_channel(membera_channel_id)
        .await
        .context("unable to delete channel")?;
    let memberb_channel_id = recv1.channel_id();
    memberb_afc
        .delete_channel(memberb_channel_id)
        .await
        .context("unable to delete channel")?;

    let membera_channel_id = chan2.channel_id();
    membera_afc
        .delete_channel(membera_channel_id)
        .await
        .context("unable to delete channel")?;
    let memberb_channel_id = recv2.channel_id();
    memberb_afc
        .delete_channel(memberb_channel_id)
        .await
        .context("unable to delete channel")?;

    Ok(())
}
