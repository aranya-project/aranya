//! Team setup for ring convergence tests.

use anyhow::{bail, Context, Result};
use aranya_client::{
    client::TeamId, config::CreateTeamConfig, AddTeamConfig, AddTeamQuicSyncConfig,
    CreateTeamQuicSyncConfig,
};
use tracing::{info, instrument};

use crate::ring::RingCtx;

impl RingCtx {
    /// Creates a team with node 0 as owner and adds all other nodes.
    ///
    /// This is the main entry point for team setup that combines team creation,
    /// adding the team to all nodes, and adding all nodes as team members.
    #[instrument(skip(self))]
    pub async fn setup_team(&mut self) -> Result<TeamId> {
        let team_id = self.create_team().await?;
        self.add_team_to_all_nodes().await?;
        self.add_all_nodes_to_team().await?;
        Ok(team_id)
    }

    /// Creates a team with node 0 as the owner.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/main/docs/multi-daemon-convergence-test.md#team-001
    //# A single team MUST be created by node 0 (the designated owner).
    #[instrument(skip(self))]
    pub async fn create_team(&mut self) -> Result<TeamId> {
        info!("Creating team with node 0 as owner");

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/main/docs/multi-daemon-convergence-test.md#team-003
        //# A shared QUIC sync seed MUST be distributed to all nodes during team setup.
        let owner_cfg = CreateTeamConfig::builder()
            .quic_sync(
                CreateTeamQuicSyncConfig::builder()
                    .seed_ikm(self.seed_ikm)
                    .build()?,
            )
            .build()?;

        let team = self.nodes[0]
            .client
            .create_team(owner_cfg)
            .await
            .context("unable to create team")?;

        let team_id = team.team_id();
        self.team_id = Some(team_id);

        info!(?team_id, "Team created");
        Ok(team_id)
    }

    /// Adds the team configuration to all non-owner nodes.
    #[instrument(skip(self))]
    pub async fn add_team_to_all_nodes(&mut self) -> Result<()> {
        let team_id = self.team_id.context("Team not created")?;

        info!(
            node_count = self.nodes.len() - 1,
            "Adding team to all nodes"
        );

        let cfg = AddTeamConfig::builder()
            .team_id(team_id)
            .quic_sync(
                AddTeamQuicSyncConfig::builder()
                    .seed_ikm(self.seed_ikm)
                    .build()?,
            )
            .build()?;

        // Add team to all nodes except node 0 (the owner)
        for node in &self.nodes[1..] {
            node.client
                .add_team(cfg.clone())
                .await
                .with_context(|| format!("unable to add team to node {}", node.index))?;
        }

        info!("Team added to all nodes");
        Ok(())
    }

    /// Adds all nodes to the team as members.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/main/docs/multi-daemon-convergence-test.md#team-002
    //# All nodes MUST be added to the team before convergence testing begins.
    #[instrument(skip(self))]
    pub async fn add_all_nodes_to_team(&mut self) -> Result<()> {
        let team_id = self.team_id.context("Team not created")?;
        let owner_team = self.nodes[0].client.team(team_id);

        info!(
            node_count = self.nodes.len() - 1,
            "Adding all nodes to team as members"
        );

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/main/docs/multi-daemon-convergence-test.md#team-004
        //# Each non-owner node MUST be added as a team member by the owner.
        for node in &self.nodes[1..] {
            owner_team
                .add_device(node.pk.clone(), None)
                .await
                .with_context(|| format!("unable to add node {} to team", node.index))?;
        }

        info!("All nodes added to team");
        Ok(())
    }

    /// Verifies that all nodes have received the team configuration.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/main/docs/multi-daemon-convergence-test.md#team-005
    //# Team configuration MUST be synchronized to all nodes before the convergence test phase.

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/main/docs/multi-daemon-convergence-test.md#team-006
    //# The test MUST verify that all nodes have received the team configuration.
    #[instrument(skip(self))]
    pub async fn verify_team_propagation(&self) -> Result<()> {
        let team_id = self.team_id.context("Team not created")?;
        let expected_device_count = self.nodes.len();

        info!(
            expected_device_count,
            "Verifying team propagation to all nodes"
        );

        for (i, node) in self.nodes.iter().enumerate() {
            let devices = node
                .client
                .team(team_id)
                .devices()
                .await
                .with_context(|| format!("unable to query devices from node {i}"))?;

            let count = devices.iter().count();

            if count != expected_device_count {
                bail!(
                    "Node {} has {} devices, expected {}",
                    i,
                    count,
                    expected_device_count
                );
            }
        }

        info!("Team propagation verified on all nodes");
        Ok(())
    }

    /// Performs a manual sync from all nodes to ensure team configuration propagates.
    ///
    /// This is used during setup before the ring topology is configured.
    #[instrument(skip(self))]
    pub async fn sync_team_from_owner(&self) -> Result<()> {
        let team_id = self.team_id.context("Team not created")?;
        let owner_addr = self.nodes[0].aranya_local_addr().await?;

        info!(
            node_count = self.nodes.len() - 1,
            "Syncing team configuration from owner"
        );

        // Sync all non-owner nodes with the owner
        for node in &self.nodes[1..] {
            node.client
                .team(team_id)
                .sync_now(owner_addr, None)
                .await
                .with_context(|| format!("node {} unable to sync with owner", node.index))?;
        }

        info!("Team sync completed");
        Ok(())
    }
}
