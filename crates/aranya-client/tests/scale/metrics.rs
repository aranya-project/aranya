//! Performance metrics calculation for scale convergence tests.

use std::time::Duration;

use tracing::info;

use crate::scale::TestCtx;

/// Performance metrics from a convergence test run.
#[derive(Clone, Debug)]
pub struct ConvergenceMetrics {
    /// Number of nodes in the test.
    pub node_count: usize,
    /// Minimum convergence time (fastest node).
    pub min_time: Duration,
    /// Maximum convergence time (slowest node).
    pub max_time: Duration,
    /// Mean convergence time.
    pub mean_time: Duration,
    /// Median convergence time.
    pub median_time: Duration,
    /// Standard deviation of convergence times.
    pub std_dev: Duration,
    /// Total time from command issuance to full convergence.
    pub total_convergence_time: Option<Duration>,
}

impl TestCtx {
    /// Calculates and reports performance metrics.
    //= docs/multi-daemon-convergence-test.md#perf-002
    //# The test MUST record the timestamp when each node achieves convergence.
    //= docs/multi-daemon-convergence-test.md#perf-003
    //# The test MUST calculate and report the following metrics:
    //# - Minimum convergence time (fastest node)
    //# - Maximum convergence time (slowest node)
    //# - Mean convergence time
    //# - Median convergence time
    //# - Standard deviation of convergence times
    pub fn calculate_metrics(&self) -> Option<ConvergenceMetrics> {
        let command_issued = self.tracker.timestamps.command_issued;

        // Collect convergence times relative to command issuance
        // Exclude the source node from metrics (it already has the command)
        let mut times: Vec<Duration> = self
            .tracker
            .node_status
            .iter()
            .enumerate()
            .filter(|(i, s)| *i != self.tracker.source_node && s.convergence_time.is_some())
            .map(|(_, s)| s.convergence_time.unwrap().duration_since(command_issued))
            .collect();

        if times.is_empty() {
            return None;
        }

        times.sort();

        let min_time = *times.first().unwrap();
        let max_time = *times.last().unwrap();

        let sum: Duration = times.iter().sum();
        let mean_time = sum / times.len() as u32;

        let median_time = if times.len().is_multiple_of(2) {
            let mid = times.len() / 2;
            (times[mid - 1] + times[mid]) / 2
        } else {
            times[times.len() / 2]
        };

        // Standard deviation
        let n = u32::try_from(times.len()).expect("node count fits in u32");
        let mean_secs = mean_time.as_secs_f64();
        let variance: f64 = times
            .iter()
            .map(|t| {
                let diff = t.as_secs_f64() - mean_secs;
                diff * diff
            })
            .sum::<f64>()
            / f64::from(n);
        let std_dev = Duration::from_secs_f64(variance.sqrt());

        let total_convergence_time = self
            .tracker
            .timestamps
            .full_convergence
            .map(|fc| fc.duration_since(command_issued));

        Some(ConvergenceMetrics {
            node_count: self.nodes.len(),
            min_time,
            max_time,
            mean_time,
            median_time,
            std_dev,
            total_convergence_time,
        })
    }

    /// Reports performance metrics to the console.
    pub fn report_metrics(&self) {
        match self.calculate_metrics() {
            Some(metrics) => {
                println!("\n=== Convergence Metrics ===");
                println!("Nodes: {}", metrics.node_count);
                println!("Min convergence time:    {:?}", metrics.min_time);
                println!("Max convergence time:    {:?}", metrics.max_time);
                println!("Mean convergence time:   {:?}", metrics.mean_time);
                println!("Median convergence time: {:?}", metrics.median_time);
                println!("Std deviation:           {:?}", metrics.std_dev);
                if let Some(total) = metrics.total_convergence_time {
                    println!("Total convergence time:  {:?}", total);
                }

                //= docs/multi-daemon-convergence-test.md#perf-004
                //# The test SHOULD report memory usage per node if available.
                #[cfg(target_os = "linux")]
                if let Some(mem) = get_process_memory_kb() {
                    println!("Process memory:          {} KB", mem);
                    println!(
                        "Est. memory per node:    {} KB",
                        mem / metrics.node_count as u64
                    );
                }

                println!("================================\n");

                info!(
                    node_count = metrics.node_count,
                    min_time_ms = metrics.min_time.as_millis(),
                    max_time_ms = metrics.max_time.as_millis(),
                    mean_time_ms = metrics.mean_time.as_millis(),
                    median_time_ms = metrics.median_time.as_millis(),
                    std_dev_ms = metrics.std_dev.as_millis(),
                    total_time_ms = metrics.total_convergence_time.map(|d| d.as_millis()),
                    "Convergence metrics"
                );
            }
            None => {
                println!("\n=== Convergence Metrics ===");
                println!("No convergence data available");
                println!("================================\n");
            }
        }
    }
}

/// Gets the current process memory usage in KB (Linux only).
#[cfg(target_os = "linux")]
fn get_process_memory_kb() -> Option<u64> {
    use std::fs;

    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}
