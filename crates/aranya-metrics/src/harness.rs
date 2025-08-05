//! This module contains the metrics harness used to measure CPU, disk, and memory usage for a
//! process.
//!
//! This is done by using a combination of syscalls to collect metrics from the host OS without
//! having much of an impact on the actual measurement. Note that unless the code being ran is on a
//! separate process, it's impossible to fully remove the effect of measuring a process. See the
//! [observer problem] for more details.
//!
//! Specifically, this uses `proc_pidinfo` or `rusage` on MacOS to collect CPU and memory usage,
//! falling back to the `sysinfo` crate for disk usage stats.
//!
//! [observer problem]: https://w.wiki/Ekxn
use std::time::Instant;

use anyhow::{anyhow, Result};
use metrics::{describe_gauge, describe_histogram, gauge, histogram};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tracing::{debug, warn};

use crate::backend::{DebugLogType, MetricsConfig};

/// Collector for process metrics, uses native APIs when possible.
#[derive(Debug)]
pub struct ProcessMetricsCollector {
    /// Config options for the current run
    config: MetricsConfig,
    /// All child process PIDs for tracking
    pids: Vec<(&'static str, u32)>,
    /// System struct for sysinfo fallback
    system: System,
    /// Collection start time for rate calculations
    _start_time: Instant,
    /// Total cumulative metrics for this run
    total_metrics: AggregatedMetrics,
    // TODO(nikki): total metrics for each process
}

/// Contains the metrics collected for all processes.
#[derive(Debug)]
struct AggregatedMetrics {
    /// The moment we start collecting metrics, used to calculate the delta of how long it took.
    timestamp: Instant,
    /// The total time the CPU spent in userspace.
    total_cpu_user_time_us: u64,
    /// The total time the CPU spent processing syscalls.
    total_cpu_system_time_us: u64,
    /// The total number of bytes used all processes.
    total_memory_bytes: u64,
    /// The total number of bytes read from disk by all processes.
    total_disk_read_bytes: u64,
    /// The total number of bytes written to disk by all processes.
    total_disk_write_bytes: u64,

    // TODO(nikki): hook the TCP/QUIC syncer with a metrics macro.
    //total_network_rx_bytes: u64,
    //total_network_tx_bytes: u64,
    /// The current number of processes we're collecting metrics about.
    process_count: usize,
}

impl Default for AggregatedMetrics {
    fn default() -> Self {
        Self {
            timestamp: Instant::now(),
            total_cpu_user_time_us: 0,
            total_cpu_system_time_us: 0,
            total_memory_bytes: 0,
            total_disk_read_bytes: 0,
            total_disk_write_bytes: 0,
            process_count: 0,
        }
    }
}

/// Contains the metrics collected for a single process.
#[derive(Debug, Default)]
#[allow(dead_code)]
struct SingleProcessMetrics {
    /// The total time the CPU spent in userspace.
    cpu_user_time_us: u64,
    /// The total time the CPU spent processing syscalls.
    cpu_system_time_us: u64,
    /// The total number of bytes used.
    memory_bytes: u64,
    /// The total number of bytes read from disk.
    disk_read_bytes: u64,
    /// The total number of bytes written to disk.
    disk_write_bytes: u64,
}

impl ProcessMetricsCollector {
    /// Create a new instance to collect process metrics.
    pub fn new(config: MetricsConfig, pids: Vec<(&'static str, u32)>) -> Self {
        Self::register_metrics();

        Self {
            config,
            pids,
            system: System::default(),
            _start_time: Instant::now(),
            total_metrics: AggregatedMetrics::default(),
        }
    }

    /// Register a description for all the gauges, histograms, and counters we use.
    fn register_metrics() {
        // Accumulated values from across the run
        describe_gauge!(
            "cpu_user_time_microseconds_total",
            "Total User CPU time consumed by all monitored processes in microseconds"
        );
        describe_gauge!(
            "cpu_system_time_microseconds_total",
            "Total System CPU time consumed by all monitored processes in microseconds"
        );
        describe_gauge!(
            "memory_total_bytes",
            "Total memory usage across all monitored processes"
        );
        describe_gauge!(
            "disk_read_bytes_total",
            "Total bytes read from disk by all monitored processes"
        );
        describe_gauge!(
            "disk_write_bytes_total",
            "Total bytes written to disk by all monitored processes"
        );

        // Other miscellaneous helpful datapoints
        describe_gauge!(
            "monitored_processes_count",
            "Number of processes being monitored"
        );
        // TODO(nikki): histograms for user/system time
        describe_histogram!(
            "metrics_collection_duration_microseconds",
            "Time spent collecting metrics in microseconds"
        );
    }

    /// Collects metrics for each process and reports them to the configured exporter.
    fn collect_metrics(&mut self) -> Result<()> {
        let collection_start = Instant::now();

        // Collect metrics for the current moment
        let current = self.collect_aggregated_metrics()?;

        // Calculate our totals
        self.total_metrics = AggregatedMetrics {
            timestamp: current.timestamp,
            process_count: current.process_count,
            total_cpu_user_time_us: current.total_cpu_user_time_us,
            total_cpu_system_time_us: current.total_cpu_system_time_us,
            total_memory_bytes: current.total_memory_bytes,
            // These need to be cumulative since sysinfo only returns bytes since last refresh.
            total_disk_read_bytes: self.total_metrics.total_disk_read_bytes
                + current.total_disk_read_bytes,
            total_disk_write_bytes: self.total_metrics.total_disk_write_bytes
                + current.total_disk_write_bytes,
        };

        debug!("Total Metrics (cumulative): {:?}", self.total_metrics);

        // Push those values to our backend
        self.report_metrics_info()?;

        // Record how long it took us to actually collect those metrics
        #[allow(clippy::cast_precision_loss)]
        histogram!("metrics_collection_duration_microseconds")
            .record(collection_start.elapsed().as_micros() as f64);

        Ok(())
    }

    /// Collects metrics for all processes and aggregates them.
    fn collect_aggregated_metrics(&mut self) -> Result<AggregatedMetrics> {
        let mut metrics = AggregatedMetrics {
            timestamp: Instant::now(),
            total_cpu_user_time_us: 0,
            total_cpu_system_time_us: 0,
            total_memory_bytes: 0,
            total_disk_read_bytes: 0,
            total_disk_write_bytes: 0,
            //total_network_rx_bytes: 0,
            //total_network_tx_bytes: 0,
            process_count: 0,
        };

        let mut removals = Vec::with_capacity(self.pids.len());
        for (index, &pid) in self.pids.clone().iter().enumerate() {
            if let Err(e) = self.collect_process_metrics(pid, &mut metrics) {
                warn!(
                    "Failed to collect metrics for \"{}\", PID {}: {e}",
                    pid.0, pid.1
                );
                removals.push(index);
            }
        }

        self.pids
            .retain(|&pid| !removals.contains(&(pid.1 as usize)));

        metrics.process_count = self.pids.len();

        Ok(metrics)
    }

    /// Collects metrics for a specific process, using a number of syscalls.
    #[cfg(target_os = "macos")]
    fn collect_process_metrics(
        &mut self,
        pid: (&'static str, u32),
        metrics: &mut AggregatedMetrics,
    ) -> Result<()> {
        // First, let's collect metrics for the individual process.
        let mut process_metrics = SingleProcessMetrics::default();

        // Collect what we can using native syscalls, and fall back to sysinfo for disk stats.
        self.collect_native_macos_metrics(pid.1, &mut process_metrics)?;
        self.collect_sysinfo_disk_metrics(pid.1, &mut process_metrics)?;

        // Aggregate this process's metrics towards the total.
        metrics.total_cpu_user_time_us += process_metrics.cpu_user_time_us;
        metrics.total_cpu_system_time_us += process_metrics.cpu_system_time_us;
        metrics.total_memory_bytes += process_metrics.memory_bytes;
        metrics.total_disk_read_bytes += process_metrics.disk_read_bytes;
        metrics.total_disk_write_bytes += process_metrics.disk_write_bytes;

        if matches!(self.config.debug_logs, DebugLogType::PerProcess) {
            debug!(
                "Process Metrics (last tick) for \"{}\", PID {}: {process_metrics:?}",
                pid.0, pid.1
            );
        }

        Ok(())
    }

    /// Collects metrics for a specific process, using a number of syscalls.
    #[cfg(not(target_os = "macos"))]
    #[allow(dead_code)]
    fn collect_process_metrics(
        &self,
        _pid: (&'static str, u32),
        _metrics: &mut AggregatedMetrics,
    ) -> Result<()> {
        // TODO(nikki): Linux support using /proc/{PID}
        Err(anyhow!(
            "We don't currently support {} for metrics, sorry!",
            std::env::consts::OS
        ))
    }

    /// Collects metrics for a specific process, using native MacOS syscalls.
    #[cfg(target_os = "macos")]
    fn collect_native_macos_metrics(
        &self,
        pid: u32,
        process_metrics: &mut SingleProcessMetrics,
    ) -> Result<()> {
        use std::{io, mem};
        // SAFETY: This has no alignment requirements, so mem::zeroed is safe.
        let mut task_info = unsafe { mem::zeroed::<libc::proc_taskinfo>() };

        #[allow(clippy::cast_possible_wrap)]
        let pid = pid as libc::pid_t;

        #[allow(clippy::cast_possible_wrap)]
        // SAFETY: We should have a valid PID, as well as buffer.
        let result = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTASKINFO,
                0,
                &raw mut task_info as *mut libc::c_void,
                size_of::<libc::proc_taskinfo>() as libc::c_int,
            )
        };

        // TODO(nikki): follow sysinfo's integrations more closely, in case this fails? We have the
        // option of proc_pid_rusage which gives PID-level information as well.

        // NOTE: -1 means error, otherwise it returns the number of bytes obtained.
        if result < 0 {
            return Err(io::Error::from_raw_os_error(result).into());
        }

        #[allow(clippy::cast_sign_loss)]
        if result as usize != size_of::<libc::proc_taskinfo>() {
            return Err(anyhow!("Unable to obtain `proc_taskinfo` for PID {pid}!"));
        }

        // These are in nanoseconds, convert to microseconds. TODO(nikki): more precision?
        process_metrics.cpu_user_time_us = task_info.pti_total_user / 1000;
        process_metrics.cpu_system_time_us = task_info.pti_total_system / 1000;

        process_metrics.memory_bytes = task_info.pti_resident_size;
        // TODO(nikki): collect more fields? We can get page faults, syscall counts, and more.
        Ok(())
    }

    /// Collects disk usage metrics using sysinfo for a process.
    #[allow(dead_code)]
    fn collect_sysinfo_disk_metrics(
        &mut self,
        pid: u32,
        process_metrics: &mut SingleProcessMetrics,
    ) -> Result<()> {
        let pid = Pid::from_u32(pid);
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            false,
            ProcessRefreshKind::nothing().with_disk_usage(),
        );

        // Note that this disk usage is "since last refresh", which in our case is last tick.
        if let Some(process) = self.system.process(pid) {
            let disk_usage = process.disk_usage();
            process_metrics.disk_read_bytes = disk_usage.read_bytes;
            process_metrics.disk_write_bytes = disk_usage.written_bytes;
        }

        Ok(())
    }

    /// Reports metrics to any exporter that may be configured.
    fn report_metrics_info(&self) -> Result<()> {
        // Update all absolute metrics.
        // TODO(nikki): add tags for individual PIDs so we can track each daemon?
        let total = &self.total_metrics;

        #[allow(clippy::cast_precision_loss)]
        {
            gauge!("cpu_user_time_microseconds_total").set(total.total_cpu_user_time_us as f64);
            gauge!("cpu_system_time_microseconds_total").set(total.total_cpu_system_time_us as f64);
            gauge!("memory_total_bytes").set(total.total_memory_bytes as f64);
            gauge!("disk_read_bytes_total").set(total.total_disk_read_bytes as f64);
            gauge!("disk_write_bytes_total").set(total.total_disk_write_bytes as f64);
            gauge!("monitored_processes_count").set(total.process_count as f64);
        }

        Ok(())
    }

    /// Spins up a loop that waits for a specific interval and then runs metrics collection.
    pub async fn start_collection_loop(&mut self) -> Result<()> {
        let mut interval = tokio::time::interval(self.config.interval);

        loop {
            interval.tick().await;
            if let Err(e) = self.collect_metrics() {
                warn!("Failed to collect metrics: {e}");
            }
        }
    }
}
