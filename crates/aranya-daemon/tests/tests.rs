//! Integration tests for the daemon.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    rust_2018_idioms
)]

use anyhow::{Context, Result};
use aranya_daemon::{aranya::Actions, policy::Effect};
use serial_test::serial;
use test_log::test;
use test_util::{contains_effect, TestCtx, TestDevices};

/// Smoke test for [`TestCtx::new_group`].
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_new_group() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    ctx.new_group(2).await.context("unable to create clients")?;
    Ok(())
}

/// Tests creating a devices.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_create_team() -> Result<()> {
    let mut ctx = TestCtx::new()?;

    ctx.new_team().await.context("unable to create team")?;
    Ok(())
}

/// Tests removing members.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_remove_members() -> Result<()> {
    let mut ctx = TestCtx::new()?;

    let team = ctx.new_team().await?;
    let devices = TestDevices::new(&team.devices);

    let effects = devices
        .owner
        .actions()
        .remove_member(devices.membera.pk.ident_pk.id()?)
        .await
        .context("unable to remove membera")?;
    if !contains_effect!(&effects, Effect::MemberRemoved(e) if e.device_id ==  devices.membera.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected MemberRemoved effect: {:?}", effects)
    }
    let effects = devices
        .owner
        .actions()
        .remove_member(devices.memberb.pk.ident_pk.id()?)
        .await
        .context("unable to remove memberb")?;
    if !contains_effect!(&effects, Effect::MemberRemoved(e) if e.device_id ==  devices.memberb.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected MemberRemoved effect: {:?}", effects)
    }
    devices.admin.sync(devices.operator).await?;
    devices
        .owner
        .actions()
        .revoke_role(
            devices.operator.pk.ident_pk.id()?,
            team.roles.operator.role_id.into(),
        )
        .await?;
    let effects = devices
        .owner
        .actions()
        .remove_member(devices.operator.pk.ident_pk.id()?)
        .await
        .context("unable to remove operator")?;
    if !contains_effect!(&effects, Effect::MemberRemoved(e) if e.device_id ==  devices.operator.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected OperatorRemoved effect: {:?}", effects)
    }
    devices
        .owner
        .actions()
        .revoke_role(
            devices.admin.pk.ident_pk.id()?,
            team.roles.admin.role_id.into(),
        )
        .await?;
    let effects = devices
        .owner
        .actions()
        .remove_member(devices.admin.pk.ident_pk.id()?)
        .await
        .context("unable to remove admin")?;
    if !contains_effect!(&effects, Effect::MemberRemoved(e) if e.device_id ==  devices.admin.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected AdminRemoved effect: {:?}", effects)
    }
    // TODO: should an owner be able to remove itself?
    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[cfg(feature = "afc")]
// TODO(nikki): we should add separate tests for AQC once that's in
// See https://github.com/aranya-project/aranya-core/issues/101
async fn test_afc_bidirectional_channel() -> Result<()> {
    #[cfg(any())]
    {
        let mut ctx = TestCtx::new()?;

        let clients = ctx.new_team().await?;
        let team = TestDevices::new(&clients);

        let label = Label::new(1);

        // TODO: assign label with operator when it works.
        devices.operator.sync(devices.owner).await?;
        devices
            .operator
            .actions()
            .define_afc_label(label)
            .await
            .context("unable to define label")?;
        devices
            .operator
            .actions()
            .assign_afc_label(devices.membera.pk.ident_pk.id()?, label, ChanOp::ReadWrite)
            .await
            .context("unable to assign label to membera")?;
        devices
            .operator
            .actions()
            .assign_afc_label(devices.memberb.pk.ident_pk.id()?, label, ChanOp::ReadWrite)
            .await
            .context("unable to assign label to memberb")?;
        devices.membera.sync(devices.operator).await?;
        devices.memberb.sync(devices.operator).await?;

        devices
            .membera
            .actions()
            .create_afc_bidi_channel(devices.memberb.pk.ident_pk.id()?, label)
            .await
            .context("unable to create bidi channel")?;
    }

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[cfg(any())]
async fn test_revoke_afc_label() -> Result<()> {
    let mut ctx = TestCtx::new()?;

    let clients = ctx.new_team().await?;
    let team = TestDevices::new(&clients);
    let label = Label::new(1);

    devices.operator.sync(devices.owner).await?;
    devices
        .operator
        .actions()
        .define_label(label)
        .await
        .context("unable to define label")?;
    devices
        .operator
        .actions()
        .assign_label(devices.membera.pk.ident_pk.id()?, label, ChanOp::SendRecv)
        .await
        .context("unable to assign label to membera")?;
    devices
        .operator
        .actions()
        .assign_label(devices.memberb.pk.ident_pk.id()?, label, ChanOp::SendRecv)
        .await
        .context("unable to assign label to memberb")?;
    devices.membera.sync(devices.operator).await?;
    devices.memberb.sync(devices.operator).await?;
    devices
        .membera
        .actions()
        .create_afc_bidi_channel(devices.memberb.pk.ident_pk.id()?, label)
        .await
        .context("unable to create bidi channel")?;

    let effects = team
        .operator
        .actions()
        .revoke_label(devices.membera.pk.ident_pk.id()?, label)
        .await
        .context("unable to revoke label membera")?;
    if !contains_effect!(&effects, Effect::LabelRevoked(e) if e.device_id == devices.membera.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected AfcLabelRevoked effect: {:?}", effects)
    }
    let effects = team
        .operator
        .actions()
        .revoke_label(devices.memberb.pk.ident_pk.id()?, label)
        .await
        .context("unable to revoke label memberb")?;
    if !contains_effect!(&effects, Effect::LabelRevoked(e) if e.device_id ==  devices.memberb.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected AfcLabelRevoked effect: {:?}", effects)
    }

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[cfg(any())]
async fn test_afc_unidirectional_channels() -> Result<()> {
    let mut ctx = TestCtx::new()?;

    let clients = ctx.new_team().await?;
    let team = TestDevices::new(&clients);

    let label1 = Label::new(1);

    devices
        .operator
        .actions()
        .define_label(label1)
        .await
        .context("unable to define label")?;

    devices
        .operator
        .actions()
        .assign_label(devices.membera.pk.ident_pk.id()?, label1, ChanOp::RecvOnly)
        .await
        .context("unable to assign label1 membera")?;
    devices
        .operator
        .actions()
        .assign_label(devices.memberb.pk.ident_pk.id()?, label1, ChanOp::SendOnly)
        .await
        .context("unable to assign label1 memberb")?;
    devices.membera.sync(devices.operator).await?;
    devices.memberb.sync(devices.operator).await?;

    devices
        .membera
        .actions()
        .create_afc_uni_channel(
            devices.memberb.pk.ident_pk.id()?,
            devices.membera.pk.ident_pk.id()?,
            label1,
        )
        .await
        .context("unable to create uni channel label1")?;

    let label2 = Label::new(2);

    devices
        .operator
        .actions()
        .define_label(label2)
        .await
        .context("unable to define label")?;

    devices
        .operator
        .actions()
        .assign_label(devices.membera.pk.ident_pk.id()?, label2, ChanOp::SendOnly)
        .await
        .context("unable to assign label2 to membera")?;
    devices
        .operator
        .actions()
        .assign_label(devices.memberb.pk.ident_pk.id()?, label2, ChanOp::RecvOnly)
        .await
        .context("unable to assign label2 to memberb")?;
    devices.membera.sync(devices.operator).await?;
    devices.memberb.sync(devices.operator).await?;

    devices
        .memberb
        .actions()
        .create_afc_uni_channel(
            devices.membera.pk.ident_pk.id()?,
            devices.memberb.pk.ident_pk.id()?,
            label2,
        )
        .await
        .context("unable to create uni channel label2")?;

    Ok(())
}
