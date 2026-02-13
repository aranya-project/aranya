//! This module contains the metrics harness used to measure CPU, disk, and memory usage for a
//! process.
//!
//! This is done by using a combination of syscalls to collect metrics from the host OS without
//! having much of an impact on the actual measurement. Note that unless the code being ran is on a
//! separate process, it's impossible to fully remove the effect of measuring a process. See the
//! [observer problem] for more details.
//!
//! Specifically, this uses `proc_pidinfo` on MacOS and `/proc/{PID}/stat` on Linux to collect CPU
//! and memory usage, falling back to the `sysinfo` crate for disk usage stats.
//!
//! [observer problem]: https://w.wiki/Ekxn
use std::{collections::HashMap, fmt, time::Instant};

use anyhow::{anyhow, Result};
use metrics::{describe_gauge, describe_histogram, gauge, histogram};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use tracing::{debug, warn};

use crate::backend::MetricsConfig;

/// Helper type for PIDs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pid {
    /// The actual Process Identifier, given from [`Child::id()`](std::process::Child::id).
    pub pid: u32,
    /// A "friendly name" for this particular process.
    pub name: &'static str,
}

impl Pid {
    /// Constructs a Pid from a u32 and str.
    pub fn from_u32(pid: u32, name: &'static str) -> Self {
        Self { pid, name }
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Collector for process metrics, uses native APIs when possible.
#[derive(Debug)]
pub struct ProcessMetricsCollector {
    /// Config options for the current run
    config: MetricsConfig,
    /// All child process PIDs for tracking
    pids: Vec<Pid>,
    /// System struct for sysinfo fallback
    system: System,
    /// Collection start time for rate calculations
    _start_time: Instant,
    /// Total cumulative metrics for this run
    total_metrics: ProcessMetrics,
    /// Total cumulative metrics for individual processes
    individual_metrics: HashMap<Pid, ProcessMetrics>,
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
            "User Time: {}ms, System Time: {}ms, Physical Memory: {}, Disk Reads: {}, Disk Writes: {}",
            self.cpu_user_time_us as f64 / 1000.0,
            self.cpu_system_time_us as f64 / 1000.0,
            scale_bytes(self.physical_memory_bytes),
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

/// Raw fields parsed from `/proc/{PID}/stat`.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ProcStat {
    /// Clock ticks spent in user mode (field 14).
    utime_ticks: u64,
    /// Clock ticks spent in kernel mode (field 15).
    stime_ticks: u64,
    /// Virtual memory size in bytes (field 23).
    vsize: u64,
    /// Resident set size in pages (field 24).
    rss_pages: u64,
}

/// Parses the contents of `/proc/{PID}/stat` into a [`ProcStat`].
///
/// An example line from `/proc/1234/stat` (note: proc(5) uses 1-based field numbering):
/// ```text
/// 1234 (my-daemon) S 1 1234 1234 0 -1 4194304 500 0 0 0 150 30 0 0 20 0 4 0 5000 104857600 2560 ...
///                  ^                                    ^^^ ^^                   ^^^^^^^^^ ^^^^
///                  state                                |   stime                vsize     rss
///                  (field 3)                            utime                    (field 23) (field 24)
///                                                      (field 14)
/// ```
///
/// The `comm` field (field 2) is wrapped in parentheses and may contain spaces or
/// other parentheses, so we find the last `)` to reliably skip past it.
/// After that, fields are split by whitespace and indexed from 0
/// (where index 0 = field 3 in proc(5)).
#[cfg(target_os = "linux")]
fn parse_proc_stat(contents: &str, pid: u32) -> Result<ProcStat> {
    let rest = contents
        .rfind(')')
        .map(|i| &contents[i + 2..])
        .ok_or_else(|| anyhow!("Malformed /proc/{pid}/stat"))?;

    let fields: Vec<&str> = rest.split_whitespace().collect();

    // After the closing ')', fields are indexed from 0, original format is 1 indexed:
    //   0  = state    (field  3)
    //   11 = utime    (field 14) - clock ticks spent in user mode
    //   12 = stime    (field 15) - clock ticks spent in kernel mode
    //   20 = vsize    (field 23) - virtual memory size in bytes
    //   21 = rss      (field 24) - resident set size in pages
    if fields.len() < 22 {
        return Err(anyhow!(
            "Not enough fields in /proc/{pid}/stat (got {})",
            fields.len()
        ));
    }

    Ok(ProcStat {
        utime_ticks: fields[11].parse()?,
        stime_ticks: fields[12].parse()?,
        vsize: fields[20].parse()?,
        rss_pages: fields[21].parse()?,
    })
}

impl ProcessMetricsCollector {
    /// Create a new instance to collect process metrics.
    pub fn new(config: MetricsConfig, pids: Vec<Pid>) -> Self {
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
                    pid.name, pid.pid
                );
                removals.push(index);
            }
        }

        self.pids
            .retain(|&pid| !removals.contains(&(pid.pid as usize)));

        metrics.process_count = self.pids.len();

        Ok(metrics)
    }

    /// Collects metrics for a specific process, using a number of syscalls.
    #[cfg(target_os = "macos")]
    fn collect_process_metrics(&mut self, pid: Pid, metrics: &mut ProcessMetrics) -> Result<()> {
        use std::collections::hash_map::Entry;

        use crate::backend::DebugLogType;

        // First, let's collect metrics for the individual process.
        let mut process_metrics = ProcessMetrics::default();

        // Collect what we can using native syscalls, and fall back to sysinfo for disk stats.
        self.collect_native_macos_metrics(pid, &mut process_metrics)?;
        self.collect_sysinfo_disk_metrics(pid, &mut process_metrics)?;

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
        let result = match self.individual_metrics.entry(pid) {
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
            debug!(
                "Process Metrics for \"{}\": PID {}, {result}",
                pid.name, pid.pid
            );
        }

        Ok(())
    }

    /// Collects metrics for a specific process using the Linux `/proc` filesystem.
    #[cfg(target_os = "linux")]
    fn collect_process_metrics(&mut self, pid: Pid, metrics: &mut ProcessMetrics) -> Result<()> {
        use std::collections::hash_map::Entry;

        use crate::backend::DebugLogType;

        // First, let's collect metrics for the individual process.
        let mut process_metrics = ProcessMetrics::default();

        // Collect what we can using /proc, and fall back to sysinfo for disk stats.
        self.collect_native_linux_metrics(pid, &mut process_metrics)?;
        self.collect_sysinfo_disk_metrics(pid, &mut process_metrics)?;

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
        let result = match self.individual_metrics.entry(pid) {
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
            debug!(
                "Process Metrics for \"{}\": PID {}, {result}",
                pid.name, pid.pid
            );
        }

        Ok(())
    }

    /// Collects metrics for a specific process, using a number of syscalls.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[allow(dead_code)]
    fn collect_process_metrics(&self, _pid: Pid, _metrics: &mut ProcessMetrics) -> Result<()> {
        Err(anyhow!(
            "We don't currently support {} for metrics, sorry!",
            std::env::consts::OS
        ))
    }

    /// Collects metrics for a specific process using the Linux `/proc` filesystem.
    ///
    /// Reads `/proc/{PID}/stat` which contains CPU times (in clock ticks) and memory sizes.
    /// Fields are documented in `proc(5)`.
    #[cfg(target_os = "linux")]
    fn collect_native_linux_metrics(
        &self,
        pid: Pid,
        process_metrics: &mut ProcessMetrics,
    ) -> Result<()> {
        use std::fs;

        let stat_path = format!("/proc/{}/stat", pid.pid);
        let stat_contents = fs::read_to_string(&stat_path)
            .map_err(|e| anyhow!("Failed to read {stat_path}: {e}"))?;

        let parsed = parse_proc_stat(&stat_contents, pid.pid)?;

        // SAFETY: sysconf with _SC_CLK_TCK is always a valid call.
        let clock_ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        // SAFETY: sysconf with _SC_PAGESIZE is always a valid call.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };

        if clock_ticks_per_sec <= 0 || page_size <= 0 {
            return Err(anyhow!("Failed to query sysconf values"));
        }

        // Both values are known > 0 from the check above, so the conversion is safe.
        let ticks: u64 = clock_ticks_per_sec
            .try_into()
            .expect("clock_ticks_per_sec is positive");
        let page_size: u64 = page_size.try_into().expect("page_size is positive");

        // Convert clock ticks to microseconds: value * 1_000_000 / ticks_per_sec
        process_metrics.cpu_user_time_us = parsed
            .utime_ticks
            .checked_mul(1_000_000)
            .and_then(|v| v.checked_div(ticks))
            .ok_or_else(|| anyhow!("overflow converting utime to microseconds"))?;
        process_metrics.cpu_system_time_us = parsed
            .stime_ticks
            .checked_mul(1_000_000)
            .and_then(|v| v.checked_div(ticks))
            .ok_or_else(|| anyhow!("overflow converting stime to microseconds"))?;
        process_metrics.virtual_memory_bytes = parsed.vsize;
        process_metrics.physical_memory_bytes = parsed
            .rss_pages
            .checked_mul(page_size)
            .ok_or_else(|| anyhow!("overflow converting rss pages to bytes"))?;

        Ok(())
    }

    /// Collects metrics for a specific process, using native MacOS syscalls.
    #[cfg(target_os = "macos")]
    fn collect_native_macos_metrics(
        &self,
        pid: Pid,
        process_metrics: &mut ProcessMetrics,
    ) -> Result<()> {
        use std::{io, mem};
        // SAFETY: This has no alignment requirements, so mem::zeroed is safe.
        let mut task_info = unsafe { mem::zeroed::<libc::proc_taskinfo>() };

        // SAFETY: We should have a valid PID and buffer.
        #[allow(clippy::cast_possible_wrap)]
        let result = unsafe {
            libc::proc_pidinfo(
                pid.pid as _,
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
            return Err(anyhow!(
                "Unable to obtain `proc_taskinfo` for {}!",
                pid.name
            ));
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
        pid: Pid,
        process_metrics: &mut ProcessMetrics,
    ) -> Result<()> {
        let pid = sysinfo::Pid::from_u32(pid.pid);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that we can read metrics for the current process from /proc.
    #[cfg(target_os = "linux")]
    #[test]
    fn collect_linux_metrics_for_self() {
        // Burn some CPU so we have nonzero tick counts at 100Hz granularity.
        let mut x: u64 = 0;
        for i in 0..10_000_000u64 {
            x = std::hint::black_box(x).wrapping_add(std::hint::black_box(i));
        }
        std::hint::black_box(x);

        let pid = Pid::from_u32(std::process::id(), "self");
        let mut collector = ProcessMetricsCollector::new(MetricsConfig::default(), vec![pid]);
        let mut metrics = ProcessMetrics::default();

        collector
            .collect_process_metrics(pid, &mut metrics)
            .expect("should collect metrics for our own process");

        // CPU time (user + system) should be nonzero after the busywork above.
        let total_cpu = metrics.cpu_user_time_us + metrics.cpu_system_time_us;
        assert!(
            total_cpu > 0,
            "expected nonzero total CPU time, got user={} system={}",
            metrics.cpu_user_time_us,
            metrics.cpu_system_time_us
        );

        // RSS must be nonzero since we're a running process.
        assert!(
            metrics.physical_memory_bytes > 0,
            "expected nonzero physical memory, got {}",
            metrics.physical_memory_bytes
        );

        // Virtual memory must be nonzero.
        assert!(
            metrics.virtual_memory_bytes > 0,
            "expected nonzero virtual memory, got {}",
            metrics.virtual_memory_bytes
        );
    }

    /// Verifies parse_proc_stat with a synthetic /proc/PID/stat line.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_stat_synthetic() {
        // Realistic /proc/PID/stat content (fields from proc(5)):
        // pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt
        //   utime stime cutime cstime priority nice num_threads itrealvalue starttime vsize rss ...
        let stat = "42 (my program) S 1 42 42 0 -1 4194304 100 0 0 0 \
                    500 200 0 0 20 0 1 0 12345 104857600 2560 18446744073709551615 0 0 0 0 0 0 0 0 0";

        let parsed = parse_proc_stat(stat, 42).expect("should parse synthetic stat");
        assert_eq!(parsed.utime_ticks, 500);
        assert_eq!(parsed.stime_ticks, 200);
        assert_eq!(parsed.vsize, 104857600);
        assert_eq!(parsed.rss_pages, 2560);
    }

    /// Verifies parse_proc_stat handles comm fields with spaces and parentheses.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_stat_tricky_comm() {
        let stat = "99 (tricky (name)) S 1 99 99 0 -1 4194304 100 0 0 0 \
                    42 17 0 0 20 0 1 0 12345 8192 128 18446744073709551615 0 0 0 0 0 0 0 0 0";

        let parsed = parse_proc_stat(stat, 99).expect("should handle nested parens");
        assert_eq!(parsed.utime_ticks, 42);
        assert_eq!(parsed.stime_ticks, 17);
        assert_eq!(parsed.vsize, 8192);
        assert_eq!(parsed.rss_pages, 128);
    }

    /// Verifies parse_proc_stat returns an error for malformed input.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_stat_malformed() {
        assert!(parse_proc_stat("no closing paren", 1).is_err());
        assert!(parse_proc_stat("1 (short) S", 1).is_err());
    }

    /// Verifies that collecting metrics for a nonexistent PID returns an error.
    #[cfg(target_os = "linux")]
    #[test]
    fn collect_linux_metrics_bad_pid() {
        let pid = Pid::from_u32(u32::MAX, "nonexistent");
        let mut collector = ProcessMetricsCollector::new(MetricsConfig::default(), vec![pid]);
        let mut metrics = ProcessMetrics::default();

        let result = collector.collect_process_metrics(pid, &mut metrics);
        assert!(result.is_err(), "expected error for nonexistent PID");
    }

    /// Verifies that the full collection loop aggregates across multiple calls.
    #[cfg(target_os = "linux")]
    #[test]
    fn collect_aggregated_metrics_linux() {
        let pid = Pid::from_u32(std::process::id(), "self");
        let mut collector = ProcessMetricsCollector::new(MetricsConfig::default(), vec![pid]);

        let aggregated = collector
            .collect_aggregated_metrics()
            .expect("should aggregate metrics");

        assert_eq!(aggregated.process_count, 1);
        assert!(aggregated.physical_memory_bytes > 0);
        assert!(aggregated.virtual_memory_bytes > 0);
    }
}
