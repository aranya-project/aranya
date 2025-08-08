//! This module contains the metrics harness used to measure CPU, disk, and memory usage for a
//! process.
//!
//! This is done by using a combination of syscalls to collect metrics from the host OS without
//! having much of an impact on the actual measurement. Note that unless the code being ran is on a
//! separate process, it's impossible to fully remove the effect of measuring a process. See the
//! [observer problem] for more details.
//!
//! Specifically, this uses `proc_pidinfo` on MacOS to collect CPU and memory usage, falling back to
//! the `sysinfo` crate for disk usage stats.
//!
//! [observer problem]: https://w.wiki/Ekxn
use std::{collections::HashMap, fmt, time::Instant};

use anyhow::{anyhow, Result};
use metrics::{describe_gauge, describe_histogram, gauge, histogram};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tracing::{debug, warn};

use crate::backend::MetricsConfig;

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
    total_metrics: ProcessMetrics,
    /// Total cumulative metrics for individual processes
    individual_metrics: HashMap<u32, ProcessMetrics>,
}

/// Container struct for collected metrics data
#[derive(Debug)]
struct ProcessMetrics {
    /// Metrics collection start time for calculating deltas.
    timestamp: Instant,
    /// The time the CPU spent in userspace.
    cpu_user_time_us: u64,
    /// The time the CPU spent processing syscalls.
    cpu_system_time_us: u64,
    /// How much physical memory is being used.
    physical_memory_bytes: u64,
    /// How much virtual memory is being used.
    virtual_memory_bytes: u64,
    /// The amount of data read from disk.
    disk_read_bytes: u64,
    /// The amount of data written from disk.
    disk_write_bytes: u64,
    /// The number of processes this collection represents.
    process_count: usize,
    // TODO(nikki): these need to be collected inside aranya-daemon
    // total_network_rx_bytes: u64,
    // total_network_tx_bytes: u64,
}

impl Default for ProcessMetrics {
    fn default() -> Self {
        Self {
            timestamp: Instant::now(),
            cpu_user_time_us: 0,
            cpu_system_time_us: 0,
            physical_memory_bytes: 0,
            virtual_memory_bytes: 0,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            process_count: 1,
        }
    }
}

#[allow(clippy::cast_precision_loss)]
impl fmt::Display for ProcessMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "User Time: {}ms, System Time: {}ms, Physical Memory: {}, Virtual Memory: {}, Disk Reads: {}, Disk Writes: {}",
            self.cpu_user_time_us as f64 / 1000.0,
            self.cpu_system_time_us as f64 / 1000.0,
            scale_bytes(self.physical_memory_bytes),
            scale_bytes(self.virtual_memory_bytes),
            scale_bytes(self.disk_read_bytes),
            scale_bytes(self.disk_write_bytes)
        )
    }
}

/// Scales up a number of bytes to the nearest unit under 1024.
#[allow(clippy::cast_precision_loss)]
fn scale_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

    // We lose precision but for the sizes we care about it's probably fine
    let mut value = bytes as f64;
    let mut unit_index = 0;

    while value >= 1024.0 && unit_index < UNITS.len() {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{bytes} {}", UNITS[unit_index])
    } else {
        format!("{value:.2}{}", UNITS[unit_index])
    }
}

impl ProcessMetricsCollector {
    /// Create a new instance to collect process metrics.
    pub fn new(config: MetricsConfig, pids: Vec<(&'static str, u32)>) -> Self {
        Self::register_metrics();

        Self {
            config,
            pids,
            _start_time: Instant::now(),
            system: System::default(),
            total_metrics: ProcessMetrics::default(),
            individual_metrics: HashMap::default(),
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
            "total_memory_usage",
            "Total amount of memory used by all monitored processes (bytes)"
        );
        describe_gauge!(
            "total_virtual_memory_usage",
            "Total amount of virtual memory accessible by all monitored processes (bytes)"
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
        self.total_metrics = ProcessMetrics {
            timestamp: current.timestamp,
            process_count: current.process_count,
            cpu_user_time_us: current.cpu_user_time_us,
            cpu_system_time_us: current.cpu_system_time_us,
            physical_memory_bytes: current.physical_memory_bytes,
            virtual_memory_bytes: current.virtual_memory_bytes,
            // These need to be cumulative since sysinfo only returns bytes since last refresh.
            disk_read_bytes: self.total_metrics.disk_read_bytes + current.disk_read_bytes,
            disk_write_bytes: self.total_metrics.disk_write_bytes + current.disk_write_bytes,
        };

        debug!("Total Metrics: {}", self.total_metrics);

        // Push those values to our backend
        self.report_metrics_info()?;

        // Record how long it took us to actually collect those metrics
        #[allow(clippy::cast_precision_loss)]
        histogram!("metrics_collection_duration_microseconds")
            .record(collection_start.elapsed().as_micros() as f64);

        Ok(())
    }

    /// Collects metrics for all processes and aggregates them.
    fn collect_aggregated_metrics(&mut self) -> Result<ProcessMetrics> {
        let mut metrics = ProcessMetrics::default();

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
        metrics: &mut ProcessMetrics,
    ) -> Result<()> {
        use std::collections::hash_map::Entry;

        use crate::backend::DebugLogType;

        // First, let's collect metrics for the individual process.
        let mut process_metrics = ProcessMetrics::default();

        // Collect what we can using native syscalls, and fall back to sysinfo for disk stats.
        self.collect_native_macos_metrics(pid, &mut process_metrics)?;
        self.collect_sysinfo_disk_metrics(pid.1, &mut process_metrics)?;

        // Aggregate this process's metrics towards the total.
        metrics.cpu_user_time_us += process_metrics.cpu_user_time_us;
        metrics.cpu_system_time_us += process_metrics.cpu_system_time_us;
        metrics.physical_memory_bytes += process_metrics.physical_memory_bytes;
        metrics.virtual_memory_bytes = metrics
            .virtual_memory_bytes
            .max(process_metrics.virtual_memory_bytes);
        metrics.disk_read_bytes += process_metrics.disk_read_bytes;
        metrics.disk_write_bytes += process_metrics.disk_write_bytes;

        // Store the latest per-process metrics
        let result = match self.individual_metrics.entry(pid.1) {
            Entry::Occupied(mut entry) => {
                // Update the entries we need to accumulate
                let stored = entry.get_mut();
                process_metrics.timestamp = stored.timestamp;
                process_metrics.disk_read_bytes += stored.disk_read_bytes;
                process_metrics.disk_write_bytes += stored.disk_write_bytes;

                &mut entry.insert(process_metrics)
            }
            Entry::Vacant(entry) => entry.insert(process_metrics),
        };

        if matches!(self.config.debug_logs, DebugLogType::PerProcess) {
            debug!("Process Metrics for \"{}\": PID {}, {result}", pid.0, pid.1);
        }

        Ok(())
    }

    /// Collects metrics for a specific process, using a number of syscalls.
    #[cfg(not(target_os = "macos"))]
    #[allow(dead_code)]
    fn collect_process_metrics(
        &self,
        _pid: (&'static str, u32),
        _metrics: &mut ProcessMetrics,
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
        pid: (&'static str, u32),
        process_metrics: &mut ProcessMetrics,
    ) -> Result<()> {
        use std::{io, mem};
        // SAFETY: This has no alignment requirements, so mem::zeroed is safe.
        let mut task_info = unsafe { mem::zeroed::<libc::proc_taskinfo>() };

        // SAFETY: We should have a valid PID and buffer.
        #[allow(clippy::cast_possible_wrap)]
        let result = unsafe {
            libc::proc_pidinfo(
                pid.1 as _,
                libc::PROC_PIDTASKINFO,
                0,
                &raw mut task_info as _,
                size_of::<libc::proc_taskinfo>() as _,
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
            return Err(anyhow!("Unable to obtain `proc_taskinfo` for {}!", pid.0));
        }

        // These are in nanoseconds, convert to microseconds. TODO(nikki): more precision?
        process_metrics.cpu_user_time_us = task_info.pti_total_user / 1000;
        process_metrics.cpu_system_time_us = task_info.pti_total_system / 1000;

        process_metrics.physical_memory_bytes = task_info.pti_resident_size;
        process_metrics.virtual_memory_bytes = task_info.pti_virtual_size;
        // TODO(nikki): collect more fields? We can get page faults, syscall counts, and more.
        Ok(())
    }

    /// Collects disk usage metrics using sysinfo for a process.
    #[allow(dead_code)]
    fn collect_sysinfo_disk_metrics(
        &mut self,
        pid: u32,
        process_metrics: &mut ProcessMetrics,
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
        let total = &self.total_metrics;

        // Report the overall information
        #[allow(clippy::cast_precision_loss)]
        {
            gauge!("cpu_user_time_microseconds_total").set(total.cpu_user_time_us as f64);
            gauge!("cpu_system_time_microseconds_total").set(total.cpu_system_time_us as f64);
            gauge!("total_memory_usage").set(total.physical_memory_bytes as f64);
            gauge!("total_virtual_memory_usage").set(total.virtual_memory_bytes as f64);
            gauge!("disk_read_bytes_total").set(total.disk_read_bytes as f64);
            gauge!("disk_write_bytes_total").set(total.disk_write_bytes as f64);
            gauge!("monitored_processes_count").set(total.process_count as f64);
        }

        // Report the information for individual processes
        #[allow(clippy::cast_precision_loss)]
        for (pid, metrics) in self.individual_metrics.iter() {
            gauge!("cpu_user_time_microseconds_total", "pid" => format!("{pid}"))
                .set(metrics.cpu_user_time_us as f64);
            gauge!("cpu_system_time_microseconds_total", "pid" => format!("{pid}"))
                .set(metrics.cpu_system_time_us as f64);
            gauge!("total_memory_usage", "pid" => format!("{pid}"))
                .set(metrics.physical_memory_bytes as f64);
            gauge!("total_virtual_memory_usage", "pid" => format!("{pid}"))
                .set(metrics.virtual_memory_bytes as f64);
            gauge!("disk_read_bytes_total", "pid" => format!("{pid}"))
                .set(metrics.disk_read_bytes as f64);
            gauge!("disk_write_bytes_total", "pid" => format!("{pid}"))
                .set(metrics.disk_write_bytes as f64);
            gauge!("monitored_processes_count", "pid" => format!("{pid}"))
                .set(metrics.process_count as f64);
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
