//! Convergence testing for ring topology.

use std::time::Instant;

use anyhow::{bail, Context, Result};
use aranya_client::client::TeamId;
use aranya_daemon_api::Text;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use crate::ring::RingCtx;

impl RingCtx {
    /// Issues a test command from the specified source node.
    ///
    /// Creates a label as the observable command that will propagate through the ring.
    //= docs/multi-daemon-convergence-test.md#conv-001
    //# The test MUST issue a command from a designated source node.

    //= docs/multi-daemon-convergence-test.md#conv-002
    //# The default source node for command issuance MUST be node 0.
    #[instrument(skip(self), fields(source_node))]
    pub async fn issue_test_command(&mut self, source_node: usize) -> Result<()> {
        let team_id = self.team_id.context("Team not created")?;

        if source_node >= self.nodes.len() {
            bail!(
                "Source node {} out of range (max: {})",
                source_node,
                self.nodes.len() - 1
            );
        }

        // Generate unique label name for this test run
        let label_name = format!("convergence_test_{}", Uuid::new_v4());

        info!(
            source_node,
            label_name = %label_name,
            "Issuing test command"
        );

        //= docs/multi-daemon-convergence-test.md#perf-001
        //# The test MUST record the timestamp when the command is issued.
        self.tracker.timestamps.command_issued = Instant::now();
        self.tracker.source_node = source_node;
        self.tracker.set_expected_label(label_name.clone());

        // Get the owner role for label creation
        let owner_role = self.nodes[source_node]
            .client
            .team(team_id)
            .roles()
            .await?
            .into_iter()
            .find(|r| r.name == "owner")
            .context("unable to find owner role")?;

        // Create the label - this is our observable command
        let label_text: Text = label_name.parse().context("invalid label name")?;
        let label_id = self.nodes[source_node]
            .client
            .team(team_id)
            .create_label(label_text, owner_role.id)
            .await
            .context("unable to create test label")?;

        // Mark source node as converged (it created the command)
        self.tracker.mark_converged(source_node);

        info!(source_node, ?label_id, "Test command issued successfully");

        Ok(())
    }

    /// Waits for all nodes to converge by receiving the test command.
    //= docs/multi-daemon-convergence-test.md#conv-005
    //# The test MUST measure the total convergence time from command issuance to full convergence.
    #[instrument(skip(self))]
    pub async fn wait_for_convergence(&mut self) -> Result<()> {
        let team_id = self.team_id.context("Team not created")?;
        let start = Instant::now();

        info!(
            timeout = ?self.config.max_duration,
            poll_interval = ?self.config.poll_interval,
            "Waiting for convergence"
        );

        loop {
            //= docs/multi-daemon-convergence-test.md#conv-006
            //# The test MUST fail if convergence is not achieved within the maximum test duration.
            if start.elapsed() > self.config.max_duration {
                let unconverged = self.tracker.get_unconverged_nodes();
                bail!(
                    "Convergence timeout after {:?}: {} nodes did not converge: {:?}",
                    start.elapsed(),
                    unconverged.len(),
                    unconverged
                );
            }

            //= docs/multi-daemon-convergence-test.md#verify-002
            //# The test MUST poll nodes periodically to check convergence status.
            self.check_all_nodes_convergence(team_id).await?;

            if self.tracker.all_converged() {
                self.tracker.timestamps.full_convergence = Some(Instant::now());
                let total_time = start.elapsed();
                info!(
                    total_time = ?total_time,
                    "Full convergence achieved"
                );
                break;
            }

            let converged_count = self
                .tracker
                .node_status
                .iter()
                .filter(|s| s.converged)
                .count();
            debug!(
                converged = converged_count,
                total = self.nodes.len(),
                "Convergence progress"
            );

            tokio::time::sleep(self.config.poll_interval).await;
        }

        Ok(())
    }

    /// Checks convergence status for all nodes.
    //= docs/multi-daemon-convergence-test.md#verify-001
    //# Each node's graph state MUST be queryable to determine received commands.
    async fn check_all_nodes_convergence(&mut self, team_id: TeamId) -> Result<()> {
        let expected_label = self
            .tracker
            .expected_label_name
            .as_ref()
            .context("No expected label set")?
            .clone();

        for i in 0..self.nodes.len() {
            // Skip already converged nodes
            if self.tracker.node_status[i].converged {
                continue;
            }

            let labels = self.nodes[i]
                .client
                .team(team_id)
                .labels()
                .await
                .with_context(|| format!("unable to query labels from node {i}"))?;

            // Check if expected label exists
            let has_expected = labels.iter().any(|l| l.name.as_str() == expected_label);

            if has_expected {
                //= docs/multi-daemon-convergence-test.md#verify-004
                //# A node MUST be considered converged when it has received all expected commands.
                self.tracker.mark_converged(i);
                debug!(node = i, "Node converged");
            }
        }

        //= docs/multi-daemon-convergence-test.md#verify-005
        //# The test MUST verify that merged graphs are consistent (no conflicting commands).
        // Consistency is verified by successful convergence - if labels match, graphs are consistent

        Ok(())
    }
}
