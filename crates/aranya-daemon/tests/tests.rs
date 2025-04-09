//! Integration tests for the daemon.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    rust_2018_idioms
)]

use anyhow::{Context, Result};
use aranya_daemon::{
    aranya::Actions,
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

    let clients = ctx.new_team().await?;
    let team = TestTeam::new(&clients);

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
        let team = TestTeam::new(&clients);

        let label = Label::new(1);

        // TODO: assign label with operator when it works.
        team.operator.sync(team.owner).await?;
        team.operator
            .actions()
            .define_label(label)
            .await
            .context("unable to define label")?;
        team.operator
            .actions()
            .assign_label(team.membera.pk.ident_pk.id()?, label, ChanOp::ReadWrite)
            .await
            .context("unable to assign label to membera")?;
        team.operator
            .actions()
            .assign_label(team.memberb.pk.ident_pk.id()?, label, ChanOp::ReadWrite)
            .await
            .context("unable to assign label to memberb")?;
        team.membera.sync(team.operator).await?;
        team.memberb.sync(team.operator).await?;

        team.membera
            .actions()
            .create_afc_bidi_channel(team.memberb.pk.ident_pk.id()?, label)
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
    let team = TestTeam::new(&clients);
    let label = Label::new(1);

    team.operator.sync(team.owner).await?;
    team.operator
        .actions()
        .define_label(label)
        .await
        .context("unable to define label")?;
    team.operator
        .actions()
        .assign_label(team.membera.pk.ident_pk.id()?, label, ChanOp::ReadWrite)
        .await
        .context("unable to assign label to membera")?;
    team.operator
        .actions()
        .assign_label(team.memberb.pk.ident_pk.id()?, label, ChanOp::ReadWrite)
        .await
        .context("unable to assign label to memberb")?;
    team.membera.sync(team.operator).await?;
    team.memberb.sync(team.operator).await?;
    team.membera
        .actions()
        .create_afc_bidi_channel(team.memberb.pk.ident_pk.id()?, label)
        .await
        .context("unable to create bidi channel")?;

    let effects = team
        .operator
        .actions()
        .revoke_label(team.membera.pk.ident_pk.id()?, label)
        .await
        .context("unable to revoke label membera")?;
    if !contains_effect!(&effects, Effect::LabelRevoked(e) if e.device_id == team.membera.pk.ident_pk.id().expect("id").into())
    {
        panic!("expected AfcLabelRevoked effect: {:?}", effects)
    }
    let effects = team
        .operator
        .actions()
        .revoke_label(team.memberb.pk.ident_pk.id()?, label)
        .await
        .context("unable to revoke label memberb")?;
    if !contains_effect!(&effects, Effect::LabelRevoked(e) if e.device_id ==  team.memberb.pk.ident_pk.id().expect("id").into())
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
    let team = TestTeam::new(&clients);

    let label1 = Label::new(1);

    team.operator
        .actions()
        .define_label(label1)
        .await
        .context("unable to define label")?;

    team.operator
        .actions()
        .assign_label(team.membera.pk.ident_pk.id()?, label1, ChanOp::ReadOnly)
        .await
        .context("unable to assign label1 membera")?;
    team.operator
        .actions()
        .assign_label(team.memberb.pk.ident_pk.id()?, label1, ChanOp::WriteOnly)
        .await
        .context("unable to assign label1 memberb")?;
    team.membera.sync(team.operator).await?;
    team.memberb.sync(team.operator).await?;

    team.membera
        .actions()
        .create_afc_uni_channel(
            team.memberb.pk.ident_pk.id()?,
            team.membera.pk.ident_pk.id()?,
            label1,
        )
        .await
        .context("unable to create uni channel label1")?;

    let label2 = Label::new(2);

    team.operator
        .actions()
        .define_label(label2)
        .await
        .context("unable to define label")?;

    team.operator
        .actions()
        .assign_label(team.membera.pk.ident_pk.id()?, label2, ChanOp::WriteOnly)
        .await
        .context("unable to assign label2 to membera")?;
    team.operator
        .actions()
        .assign_label(team.memberb.pk.ident_pk.id()?, label2, ChanOp::ReadOnly)
        .await
        .context("unable to assign label2 to memberb")?;
    team.membera.sync(team.operator).await?;
    team.memberb.sync(team.operator).await?;

    team.memberb
        .actions()
        .create_afc_uni_channel(
            team.membera.pk.ident_pk.id()?,
            team.memberb.pk.ident_pk.id()?,
            label2,
        )
        .await
        .context("unable to create uni channel label2")?;

    Ok(())
}
