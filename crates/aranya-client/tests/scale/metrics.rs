//! Performance metrics calculation for scale convergence tests.

use std::{collections::HashMap, time::Duration};

use tracing::{info, warn};

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
    /// Mode convergence time (most common bucketed time).
    pub mode_time: Duration,
    /// 95th percentile convergence time.
    pub p95_time: Duration,
    /// 99th percentile convergence time.
    pub p99_time: Duration,
    /// Standard deviation of convergence times.
    pub std_dev: Duration,
    /// Total time from command issuance to full convergence.
    pub total_convergence_time: Option<Duration>,
}

impl TestCtx {
    /// Calculates and reports performance metrics.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#perf-002
    //# The test MUST record the timestamp when each node achieves convergence.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#perf-003
    //# The test MUST calculate and report the following metrics:
    //# - Minimum convergence time (fastest node)
    //# - Maximum convergence time (slowest node)
    //# - Mean convergence time
    //# - Median convergence time
    //# - Mode convergence time (convergence times SHOULD be bucketed to produce a meaningful mode)
    //# - 95th percentile convergence time (p95)
    //# - 99th percentile convergence time (p99)
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
            .filter(|(i, s)| *i != self.tracker.source_node.0 && s.convergence_time.is_some())
            .map(|(_, s)| {
                s.convergence_time
                    .expect("convergence_time must be set when filter passes")
                    .duration_since(command_issued)
            })
            .collect();

        if times.is_empty() {
            return None;
        }

        times.sort();

        let min_time = *times.first().expect("times must not be empty");
        let max_time = *times.last().expect("times must not be empty");

        let sum: Duration = times.iter().sum();
        let mean_time = sum / times.len() as u32;

        let median_time = if times.len().is_multiple_of(2) {
            let mid = times.len() / 2;
            (times[mid - 1] + times[mid]) / 2
        } else {
            times[times.len() / 2]
        };

        // Mode: bucket times into 100ms intervals to produce a meaningful mode
        let mode_time = Self::calculate_mode(&times);

        // Percentiles (using nearest-rank method)
        let p95_time = Self::percentile(&times, 95.0);
        let p99_time = Self::percentile(&times, 99.0);

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
            mode_time,
            p95_time,
            p99_time,
            std_dev,
            total_convergence_time,
        })
    }

    /// Calculates the mode by bucketing durations into 100ms intervals.
    fn calculate_mode(times: &[Duration]) -> Duration {
        let bucket_ms = 100u128;
        let mut buckets: HashMap<u128, usize> = HashMap::new();

        for t in times {
            let bucket = (t.as_millis() / bucket_ms) * bucket_ms;
            *buckets.entry(bucket).or_insert(0) += 1;
        }

        let mode_bucket = buckets
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(bucket, _)| bucket)
            .unwrap_or(0);

        Duration::from_millis(mode_bucket as u64)
    }

    /// Calculates the percentile using nearest-rank method.
    /// `times` must be sorted.
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation
    )]
    fn percentile(times: &[Duration], pct: f64) -> Duration {
        if times.is_empty() {
            return Duration::ZERO;
        }
        let rank = (pct / 100.0 * times.len() as f64).ceil() as usize;
        let index = rank.min(times.len()).saturating_sub(1);
        times[index]
    }

    /// Reports performance metrics to the console.
    pub fn report_metrics(&self) {
        match self.calculate_metrics() {
            Some(metrics) => {
                println!("\n=== Convergence Metrics [{}] ===", self.config.test_name);
                println!("Nodes: {}", metrics.node_count);
                println!("Min convergence time:    {:?}", metrics.min_time);
                println!("Max convergence time:    {:?}", metrics.max_time);
                println!("Mean convergence time:   {:?}", metrics.mean_time);
                println!("Median convergence time: {:?}", metrics.median_time);
                println!("Mode convergence time:   {:?}", metrics.mode_time);
                println!("p95 convergence time:    {:?}", metrics.p95_time);
                println!("p99 convergence time:    {:?}", metrics.p99_time);
                println!("Std deviation:           {:?}", metrics.std_dev);
                if let Some(total) = metrics.total_convergence_time {
                    println!("Total convergence time:  {:?}", total);
                }

                println!("================================\n");

                info!(
                    node_count = metrics.node_count,
                    min_time_ms = metrics.min_time.as_millis(),
                    max_time_ms = metrics.max_time.as_millis(),
                    mean_time_ms = metrics.mean_time.as_millis(),
                    median_time_ms = metrics.median_time.as_millis(),
                    mode_time_ms = metrics.mode_time.as_millis(),
                    p95_time_ms = metrics.p95_time.as_millis(),
                    p99_time_ms = metrics.p99_time.as_millis(),
                    std_dev_ms = metrics.std_dev.as_millis(),
                    total_time_ms = metrics.total_convergence_time.map(|d| d.as_millis()),
                    "Convergence metrics"
                );
            }
            None => {
                println!("\n=== Convergence Metrics [{}] ===", self.config.test_name);
                println!("No convergence data available");
                println!("================================\n");
            }
        }

        // Export CSV if the feature flag is enabled
        self.export_csv_if_enabled();
    }

    /// Exports raw convergence data as a CSV file if the `ARANYA_CSV_EXPORT` env var is set.
    ///
    /// The env var value is used as the output file path.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#perf-005
    //# When a CSV export feature flag is enabled, the test MUST output raw convergence data as a CSV file after each test run.
    fn export_csv_if_enabled(&self) {
        let csv_path = match std::env::var("ARANYA_CSV_EXPORT") {
            Ok(path) if !path.is_empty() => path,
            _ => return,
        };

        let command_issued = self.tracker.timestamps.command_issued;

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#perf-006
        //# The CSV output MUST include one row per node with the following columns: node index, label assignment time (T0), node convergence time, and convergence duration (time from T0 to node convergence).
        let mut csv = String::from("node_index,t0_secs,convergence_time_secs,duration_secs\n");

        let t0 = 0.0_f64; // T0 is the reference point (0)

        for (i, status) in self.tracker.node_status.iter().enumerate() {
            let (conv_time, duration) = match status.convergence_time {
                Some(ct) => {
                    let dur = ct.duration_since(command_issued).as_secs_f64();
                    (format!("{dur:.6}"), format!("{dur:.6}"))
                }
                None => ("N/A".to_string(), "N/A".to_string()),
            };
            csv.push_str(&format!("{i},{t0:.6},{conv_time},{duration}\n"));
        }

        match std::fs::write(&csv_path, &csv) {
            Ok(()) => info!(path = %csv_path, "CSV convergence data exported"),
            Err(e) => warn!(path = %csv_path, error = %e, "Failed to export CSV"),
        }
    }
}
