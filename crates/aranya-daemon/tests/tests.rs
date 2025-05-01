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
