//! Integration tests for the daemon.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    rust_2018_idioms
)]

use anyhow::{Context, Result};
use aranya_daemon::{
    actions::Actions,
    policy::{Effect, Role},
};
use serial_test::serial;
use test_log::test;
use test_util::{contains_effect, TestCtx, TestTeam};

/// Smoke test for [`TestCtx::new_group`].
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_new_group() -> Result<()> {
    let mut ctx = TestCtx::new()?;
    ctx.new_group(2).await.context("unable to create clients")?;
    Ok(())
}

/// Tests creating a team.
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

    let mut clients = ctx.new_team().await?;
    let team = TestTeam::new(clients.as_mut_slice());

    let effects = team
        .operator
        .actions()
        .remove_member(team.membera.pk.ident_pk.id()?)
        .await
        .context("unable to remove membera")?;
    if !contains_effect!(&effects, Effect::MemberRemoved(e) if e.device_id ==  team.membera.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected MemberRemoved effect: {:?}", effects)
    }
    let effects = team
        .operator
        .actions()
        .remove_member(team.memberb.pk.ident_pk.id()?)
        .await
        .context("unable to remove memberb")?;
    if !contains_effect!(&effects, Effect::MemberRemoved(e) if e.device_id ==  team.memberb.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected MemberRemoved effect: {:?}", effects)
    }
    team.admin.sync(team.operator).await?;
    team.owner
        .actions()
        .revoke_role(team.operator.pk.ident_pk.id()?, Role::Operator)
        .await?;
    let effects = team
        .owner
        .actions()
        .remove_member(team.operator.pk.ident_pk.id()?)
        .await
        .context("unable to remove operator")?;
    if !contains_effect!(&effects, Effect::MemberRemoved(e) if e.device_id ==  team.operator.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected OperatorRemoved effect: {:?}", effects)
    }
    team.owner
        .actions()
        .revoke_role(team.admin.pk.ident_pk.id()?, Role::Admin)
        .await?;
    let effects = team
        .owner
        .actions()
        .remove_member(team.admin.pk.ident_pk.id()?)
        .await
        .context("unable to remove admin")?;
    if !contains_effect!(&effects, Effect::MemberRemoved(e) if e.device_id ==  team.admin.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected AdminRemoved effect: {:?}", effects)
    }
    // TODO: should an owner be able to remove itself?
    Ok(())
}
