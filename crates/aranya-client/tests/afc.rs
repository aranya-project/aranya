#![allow(clippy::panic)]
#[cfg(feature = "afc")]
mod common;

#[cfg(feature = "afc")]
use {
    crate::common::DevicesCtx,
    anyhow::{bail, Context, Result},
    aranya_client::afc::{Channel, Channels},
    aranya_client::client::ChanOp,
    aranya_daemon_api::text,
};

/// Demonstrate creating a bidirectional AFC channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_bidi_chan_create() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_bidi_chan_create").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
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
        .afc()
        .create_bidi_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc bidi channel")?;

    devices
        .memberb
        .client
        .afc()
        .recv_ctrl(team_id, ctrl)
        .await
        .context("unable to receive afc bidi channel")?;

    Ok(())
}

/// Demonstrate seal/open with bidirectional AFC channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_bidi_chan_seal_open() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_bidi_chan_seal_open").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
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

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create bidi channel.
    let (chan, ctrl) = membera_afc
        .create_bidi_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc bidi channel")?;

    // Receive bidi channel.
    let Channel::Bidi(recv) = memberb_afc
        .recv_ctrl(team_id, ctrl)
        .await
        .context("unable to receive afc bidi channel")?
    else {
        bail!("expected a bidirectional receive channel");
    };

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

/// Demonstrate deleting a bidirectional AFC channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_bidi_chan_delete() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_bidi_chan_delete").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
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

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create bidi channel.
    let (chan, ctrl) = membera_afc
        .create_bidi_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc bidi channel")?;

    // Receive bidi channel.
    let Channel::Bidi(recv) = memberb_afc
        .recv_ctrl(team_id, ctrl)
        .await
        .context("unable to receive afc bidi channel")?
    else {
        bail!("expected a bidirectional receive channel");
    };

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

/// Demonstrate open/seal with multiple bidirectional AFC channels.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_bidi_multi_chans() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_bidi_multi_chans").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);

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
    let operator_addr = devices.operator.aranya_local_addr().await?;
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

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create first bidi channel.
    let (chan1, ctrl1) = membera_afc
        .create_bidi_channel(team_id, devices.memberb.id, label_id1)
        .await
        .context("unable to create afc bidi channel")?;

    // Create second bidi channel.
    let (chan2, ctrl2) = memberb_afc
        .create_bidi_channel(team_id, devices.membera.id, label_id2)
        .await
        .context("unable to create afc bidi channel")?;

    // Receive first bidi channel.
    let Channel::Bidi(recv1) = memberb_afc
        .recv_ctrl(team_id, ctrl1)
        .await
        .context("unable to receive afc bidi channel")?
    else {
        bail!("expected a bidirectional receive channel");
    };

    // Receive second bidi channel.
    let Channel::Bidi(recv2) = membera_afc
        .recv_ctrl(team_id, ctrl2)
        .await
        .context("unable to receive afc bidi channel")?
    else {
        bail!("expected a bidirectional receive channel");
    };

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
    let afc_msg = "afc msg".as_bytes();
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

/// Demonstrate creating a unidirectional AFC channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_chan_create() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_chan_create").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
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
        .afc()
        .create_uni_send_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    devices
        .memberb
        .client
        .afc()
        .recv_ctrl(team_id, ctrl)
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

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
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

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create uni channel.
    let (chan, ctrl) = membera_afc
        .create_uni_send_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let Channel::Recv(recv) = memberb_afc
        .recv_ctrl(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?
    else {
        bail!("expected a unidirectional receive channel");
    };

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

/// Demonstrate seal/open with unidirectional AFC recv channel.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_recv_chan_seal_open() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_recv_chan_seal_open").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
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

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create uni channel.
    let (recv, ctrl) = membera_afc
        .create_uni_recv_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni recv channel")?;

    // Receive uni channel.
    let Channel::Send(send) = memberb_afc
        .recv_ctrl(team_id, ctrl)
        .await
        .context("unable to receive afc uni send channel")?
    else {
        bail!("expected a unidirectional send channel");
    };

    // Seal data.
    let afc_msg = "afc msg".as_bytes();
    let mut ciphertext = vec![0u8; afc_msg.len() + Channels::OVERHEAD];
    send.seal(&mut ciphertext, afc_msg)
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

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);

    let label_id = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label_id, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label_id, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?;
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

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create uni channel.
    let (chan, ctrl) = membera_afc
        .create_uni_send_channel(team_id, devices.memberb.id, label_id)
        .await
        .context("unable to create afc uni channel")?;

    // Receive uni channel.
    let Channel::Recv(recv) = memberb_afc
        .recv_ctrl(team_id, ctrl)
        .await
        .context("unable to receive afc uni channel")?
    else {
        bail!("expected a unidirectional receive channel");
    };

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

/// Demonstrate open/seal with multiple unidirectional AFC channels.
#[cfg(feature = "afc")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_uni_multi_send_chans() -> Result<()> {
    let mut devices = DevicesCtx::new("test_afc_uni_multi_chans").await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);

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
    let operator_addr = devices.operator.aranya_local_addr().await?;
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

    let membera_afc = devices.membera.client.afc();
    let memberb_afc = devices.memberb.client.afc();

    // Create first bidi channel.
    let (chan1, ctrl1) = membera_afc
        .create_uni_send_channel(team_id, devices.memberb.id, label_id1)
        .await
        .context("unable to create afc uni channel")?;

    // Create second bidi channel.
    let (chan2, ctrl2) = memberb_afc
        .create_uni_send_channel(team_id, devices.membera.id, label_id2)
        .await
        .context("unable to create afc uni channel")?;

    // Receive first bidi channel.
    let Channel::Recv(recv1) = memberb_afc
        .recv_ctrl(team_id, ctrl1)
        .await
        .context("unable to receive afc uni channel")?
    else {
        bail!("expected a unidirectional receive channel");
    };

    // Receive second bidi channel.
    let Channel::Recv(recv2) = membera_afc
        .recv_ctrl(team_id, ctrl2)
        .await
        .context("unable to receive afc uni channel")?
    else {
        bail!("expected a unidirectional receive channel");
    };

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
