//! This module contains the metrics harness used to measure CPU, disk, and memory usage for a
//! process.
//!
//! This is done by using a combination of syscalls to collect metrics from the host OS without
//! having much of an impact on the actual measurement. Note that unless the code being ran is on a
//! separate process, it's impossible to fully remove the effect of measuring a process. See the
//! [observer problem] for more details.
//!
//! Specifically, this uses `proc_pidinfo` on macOS and `/proc/{PID}/stat` +
//! `/proc/{PID}/smaps_rollup` on Linux to collect CPU and memory usage (with
//! PSS-based detailed memory breakdown when available on kernel >= 4.14),
//! falling back to the `sysinfo` crate for disk usage stats.
//!
//! [observer problem]: https://w.wiki/Ekxn
use std::{collections::HashMap, fmt, time::Instant};

use anyhow::{Result, anyhow};
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
    /// Proportional share size in bytes (from smaps_rollup; 0 if unavailable).
    pss_bytes: u64,
    /// PSS of anonymous (heap/stack) pages in bytes.
    pss_anon_bytes: u64,
    /// PSS of file-backed pages in bytes.
    pss_file_bytes: u64,
    /// PSS of shared memory pages in bytes.
    pss_shmem_bytes: u64,
    /// Bytes currently swapped out.
    swap_bytes: u64,
    /// Private dirty (non-reclaimable) pages in bytes.
    private_dirty_bytes: u64,
    /// Shared clean (freely reclaimable) pages in bytes.
    shared_clean_bytes: u64,
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
            pss_bytes: 0,
            pss_anon_bytes: 0,
            pss_file_bytes: 0,
            pss_shmem_bytes: 0,
            swap_bytes: 0,
            private_dirty_bytes: 0,
            shared_clean_bytes: 0,
            process_count: 1,
        }
    }
}

#[allow(clippy::cast_precision_loss)]
impl fmt::Display for ProcessMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "User Time: {}ms, System Time: {}ms, Physical Memory: {}, PSS: {}, Swap: {}, \
             Disk Reads: {}, Disk Writes: {}",
            self.cpu_user_time_us as f64 / 1000.0,
            self.cpu_system_time_us as f64 / 1000.0,
            scale_bytes(self.physical_memory_bytes),
            scale_bytes(self.pss_bytes),
            scale_bytes(self.swap_bytes),
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
        unit_index = unit_index
            .checked_add(1)
            .expect("unit index should not overflow");
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
        .and_then(|i| i.checked_add(2))
        .map(|start| &contents[start..])
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

/// Raw fields parsed from `/proc/{PID}/smaps_rollup`.
///
/// All values are stored in bytes (the kernel reports them in kB).
/// Fields default to zero so that missing entries (e.g. `Pss_Anon`
/// on kernels older than 5.14) degrade gracefully.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct SmapsRollup {
    /// Total resident set size in bytes.
    rss_bytes: u64,
    /// Proportional share size in bytes.
    pss_bytes: u64,
    /// PSS of anonymous (heap/stack) pages in bytes.
    pss_anon_bytes: u64,
    /// PSS of file-backed pages in bytes.
    pss_file_bytes: u64,
    /// PSS of shared memory pages in bytes.
    pss_shmem_bytes: u64,
    /// Bytes currently swapped out.
    swap_bytes: u64,
    /// Private pages that have been written (non-reclaimable) in bytes.
    private_dirty_bytes: u64,
    /// Shared pages that are unmodified (freely reclaimable) in bytes.
    shared_clean_bytes: u64,
}

/// Parses the contents of `/proc/{PID}/smaps_rollup` into a [`SmapsRollup`].
///
/// The first line is a header (`00100000-ff709000 ---p ... [rollup]`) which is
/// skipped. Subsequent lines have the form `Key:       <value> kB`. Unknown
/// keys are silently ignored for forward compatibility with newer kernels.
#[cfg(target_os = "linux")]
fn parse_smaps_rollup(contents: &str, pid: u32) -> Result<SmapsRollup> {
    let mut result = SmapsRollup::default();

    for line in contents.lines().skip(1) {
        let (key, value) = match line.split_once(':') {
            Some(pair) => pair,
            // Skip blank or malformed lines rather than hard-failing.
            None => continue,
        };

        let key = key.trim();
        let value_str = value
            .trim()
            .strip_suffix("kB")
            .ok_or_else(|| anyhow!("Missing kB suffix in /proc/{pid}/smaps_rollup: {line}"))?
            .trim();
        let kb: u64 = value_str
            .parse()
            .map_err(|e| anyhow!("Bad value in /proc/{pid}/smaps_rollup field {key}: {e}"))?;
        let bytes = kb
            .checked_mul(1024)
            .ok_or_else(|| anyhow!("Overflow converting {key} kB to bytes"))?;

        match key {
            "Rss" => result.rss_bytes = bytes,
            "Pss" => result.pss_bytes = bytes,
            "Pss_Anon" => result.pss_anon_bytes = bytes,
            "Pss_File" => result.pss_file_bytes = bytes,
            "Pss_Shmem" => result.pss_shmem_bytes = bytes,
            "Swap" => result.swap_bytes = bytes,
            "Private_Dirty" => result.private_dirty_bytes = bytes,
            "Shared_Clean" => result.shared_clean_bytes = bytes,
            _ => {} // silently ignore unknown fields
        }
    }

    Ok(result)
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

        // Detailed memory breakdown from /proc/PID/smaps_rollup (Linux >= 4.14).
        describe_gauge!(
            "pss_bytes_total",
            "Total proportional share size in bytes (smaps_rollup)"
        );
        describe_gauge!(
            "pss_anon_bytes_total",
            "Total PSS of anonymous (heap/stack) pages in bytes"
        );
        describe_gauge!(
            "pss_file_bytes_total",
            "Total PSS of file-backed pages in bytes"
        );
        describe_gauge!(
            "pss_shmem_bytes_total",
            "Total PSS of shared memory pages in bytes"
        );
        describe_gauge!(
            "swap_bytes_total",
            "Total bytes swapped out to disk"
        );
        describe_gauge!(
            "private_dirty_bytes_total",
            "Total private dirty (non-reclaimable) pages in bytes"
        );
        describe_gauge!(
            "shared_clean_bytes_total",
            "Total shared clean (reclaimable) pages in bytes"
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
            disk_read_bytes: self
                .total_metrics
                .disk_read_bytes
                .saturating_add(current.disk_read_bytes),
            disk_write_bytes: self
                .total_metrics
                .disk_write_bytes
                .saturating_add(current.disk_write_bytes),
            // smaps_rollup fields are point-in-time snapshots (like RSS), not cumulative.
            pss_bytes: current.pss_bytes,
            pss_anon_bytes: current.pss_anon_bytes,
            pss_file_bytes: current.pss_file_bytes,
            pss_shmem_bytes: current.pss_shmem_bytes,
            swap_bytes: current.swap_bytes,
            private_dirty_bytes: current.private_dirty_bytes,
            shared_clean_bytes: current.shared_clean_bytes,
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
        metrics.cpu_user_time_us = metrics
            .cpu_user_time_us
            .saturating_add(process_metrics.cpu_user_time_us);
        metrics.cpu_system_time_us = metrics
            .cpu_system_time_us
            .saturating_add(process_metrics.cpu_system_time_us);
        metrics.physical_memory_bytes = metrics
            .physical_memory_bytes
            .saturating_add(process_metrics.physical_memory_bytes);
        metrics.virtual_memory_bytes = metrics
            .virtual_memory_bytes
            .max(process_metrics.virtual_memory_bytes);
        metrics.disk_read_bytes = metrics
            .disk_read_bytes
            .saturating_add(process_metrics.disk_read_bytes);
        metrics.disk_write_bytes = metrics
            .disk_write_bytes
            .saturating_add(process_metrics.disk_write_bytes);
        // smaps_rollup fields (always 0 on macOS, but aggregate for struct completeness).
        metrics.pss_bytes = metrics
            .pss_bytes
            .saturating_add(process_metrics.pss_bytes);
        metrics.pss_anon_bytes = metrics
            .pss_anon_bytes
            .saturating_add(process_metrics.pss_anon_bytes);
        metrics.pss_file_bytes = metrics
            .pss_file_bytes
            .saturating_add(process_metrics.pss_file_bytes);
        metrics.pss_shmem_bytes = metrics
            .pss_shmem_bytes
            .saturating_add(process_metrics.pss_shmem_bytes);
        metrics.swap_bytes = metrics
            .swap_bytes
            .saturating_add(process_metrics.swap_bytes);
        metrics.private_dirty_bytes = metrics
            .private_dirty_bytes
            .saturating_add(process_metrics.private_dirty_bytes);
        metrics.shared_clean_bytes = metrics
            .shared_clean_bytes
            .saturating_add(process_metrics.shared_clean_bytes);

        // Store the latest per-process metrics
        let result = match self.individual_metrics.entry(pid) {
            Entry::Occupied(mut entry) => {
                // Update the entries we need to accumulate
                let stored = entry.get_mut();
                process_metrics.timestamp = stored.timestamp;
                process_metrics.disk_read_bytes = process_metrics
                    .disk_read_bytes
                    .saturating_add(stored.disk_read_bytes);
                process_metrics.disk_write_bytes = process_metrics
                    .disk_write_bytes
                    .saturating_add(stored.disk_write_bytes);

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
        metrics.cpu_user_time_us = metrics
            .cpu_user_time_us
            .saturating_add(process_metrics.cpu_user_time_us);
        metrics.cpu_system_time_us = metrics
            .cpu_system_time_us
            .saturating_add(process_metrics.cpu_system_time_us);
        metrics.physical_memory_bytes = metrics
            .physical_memory_bytes
            .saturating_add(process_metrics.physical_memory_bytes);
        metrics.virtual_memory_bytes = metrics
            .virtual_memory_bytes
            .max(process_metrics.virtual_memory_bytes);
        metrics.disk_read_bytes = metrics
            .disk_read_bytes
            .saturating_add(process_metrics.disk_read_bytes);
        metrics.disk_write_bytes = metrics
            .disk_write_bytes
            .saturating_add(process_metrics.disk_write_bytes);
        // smaps_rollup fields (0 when smaps_rollup is unavailable).
        metrics.pss_bytes = metrics
            .pss_bytes
            .saturating_add(process_metrics.pss_bytes);
        metrics.pss_anon_bytes = metrics
            .pss_anon_bytes
            .saturating_add(process_metrics.pss_anon_bytes);
        metrics.pss_file_bytes = metrics
            .pss_file_bytes
            .saturating_add(process_metrics.pss_file_bytes);
        metrics.pss_shmem_bytes = metrics
            .pss_shmem_bytes
            .saturating_add(process_metrics.pss_shmem_bytes);
        metrics.swap_bytes = metrics
            .swap_bytes
            .saturating_add(process_metrics.swap_bytes);
        metrics.private_dirty_bytes = metrics
            .private_dirty_bytes
            .saturating_add(process_metrics.private_dirty_bytes);
        metrics.shared_clean_bytes = metrics
            .shared_clean_bytes
            .saturating_add(process_metrics.shared_clean_bytes);

        // Store the latest per-process metrics
        let result = match self.individual_metrics.entry(pid) {
            Entry::Occupied(mut entry) => {
                // Update the entries we need to accumulate
                let stored = entry.get_mut();
                process_metrics.timestamp = stored.timestamp;
                process_metrics.disk_read_bytes = process_metrics
                    .disk_read_bytes
                    .saturating_add(stored.disk_read_bytes);
                process_metrics.disk_write_bytes = process_metrics
                    .disk_write_bytes
                    .saturating_add(stored.disk_write_bytes);

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
    /// Reads `/proc/{PID}/stat` for CPU times and virtual memory, and
    /// `/proc/{PID}/smaps_rollup` (kernel >= 4.14) for detailed memory
    /// breakdown (PSS, swap, etc.). Falls back to RSS from `/proc/stat`
    /// when `smaps_rollup` is unavailable.
    #[cfg(target_os = "linux")]
    fn collect_native_linux_metrics(
        &self,
        pid: Pid,
        process_metrics: &mut ProcessMetrics,
    ) -> Result<()> {
        use std::fs;

        // Always read /proc/stat for CPU times and vsize.
        let stat_path = format!("/proc/{}/stat", pid.pid);
        let stat_contents = fs::read_to_string(&stat_path)
            .map_err(|e| anyhow!("Failed to read {stat_path}: {e}"))?;

        let parsed = parse_proc_stat(&stat_contents, pid.pid)?;

        // SAFETY: `sysconf` is a read-only, side-effect-free libc function.
        // `_SC_CLK_TCK` is required by POSIX.1-1996 and guaranteed to return a
        // positive value on Linux (always USER_HZ = 100, a stable kernel ABI
        // since 2.6). The only reason this is `unsafe` is the FFI boundary;
        // no pointers are passed and no memory is accessed.
        let clock_ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        // SAFETY: Same justification as above. `_SC_PAGESIZE` is required by
        // POSIX.1-2001 and always returns a positive value on Linux (typically
        // 4096 on x86_64). This module is compiled only on Linux
        // (`#[cfg(target_os = "linux")]`), so both constants are always defined.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };

        if clock_ticks_per_sec <= 0 || page_size <= 0 {
            return Err(anyhow!("Failed to query sysconf values"));
        }

        // Both values are known > 0 from the check above, so the conversion is safe.
        let ticks: u64 = clock_ticks_per_sec
            .try_into()
            .expect("clock_ticks_per_sec is positive");
        let page_size_bytes: u64 = page_size.try_into().expect("page_size is positive");

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

        // Virtual memory is always from /proc/stat (smaps_rollup does not have it).
        process_metrics.virtual_memory_bytes = parsed.vsize;

        // Memory: prefer smaps_rollup for detailed breakdown, fall back to /proc/stat RSS.
        let smaps_path = format!("/proc/{}/smaps_rollup", pid.pid);
        match fs::read_to_string(&smaps_path) {
            Ok(smaps_contents) => {
                let smaps = parse_smaps_rollup(&smaps_contents, pid.pid)?;
                process_metrics.physical_memory_bytes = smaps.rss_bytes;
                process_metrics.pss_bytes = smaps.pss_bytes;
                process_metrics.pss_anon_bytes = smaps.pss_anon_bytes;
                process_metrics.pss_file_bytes = smaps.pss_file_bytes;
                process_metrics.pss_shmem_bytes = smaps.pss_shmem_bytes;
                process_metrics.swap_bytes = smaps.swap_bytes;
                process_metrics.private_dirty_bytes = smaps.private_dirty_bytes;
                process_metrics.shared_clean_bytes = smaps.shared_clean_bytes;
            }
            Err(_) => {
                // Fallback: use RSS from /proc/stat (kernel < 4.14 or restricted access).
                debug!(
                    "smaps_rollup not available for PID {}, falling back to /proc/stat RSS",
                    pid.pid
                );
                process_metrics.physical_memory_bytes = parsed
                    .rss_pages
                    .checked_mul(page_size_bytes)
                    .ok_or_else(|| anyhow!("overflow converting rss pages to bytes"))?;
                // All smaps fields remain at their Default (0).
            }
        }

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
            gauge!("pss_bytes_total").set(total.pss_bytes as f64);
            gauge!("pss_anon_bytes_total").set(total.pss_anon_bytes as f64);
            gauge!("pss_file_bytes_total").set(total.pss_file_bytes as f64);
            gauge!("pss_shmem_bytes_total").set(total.pss_shmem_bytes as f64);
            gauge!("swap_bytes_total").set(total.swap_bytes as f64);
            gauge!("private_dirty_bytes_total").set(total.private_dirty_bytes as f64);
            gauge!("shared_clean_bytes_total").set(total.shared_clean_bytes as f64);
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
            gauge!("pss_bytes_total", "pid" => format!("{pid}"))
                .set(metrics.pss_bytes as f64);
            gauge!("pss_anon_bytes_total", "pid" => format!("{pid}"))
                .set(metrics.pss_anon_bytes as f64);
            gauge!("pss_file_bytes_total", "pid" => format!("{pid}"))
                .set(metrics.pss_file_bytes as f64);
            gauge!("pss_shmem_bytes_total", "pid" => format!("{pid}"))
                .set(metrics.pss_shmem_bytes as f64);
            gauge!("swap_bytes_total", "pid" => format!("{pid}"))
                .set(metrics.swap_bytes as f64);
            gauge!("private_dirty_bytes_total", "pid" => format!("{pid}"))
                .set(metrics.private_dirty_bytes as f64);
            gauge!("shared_clean_bytes_total", "pid" => format!("{pid}"))
                .set(metrics.shared_clean_bytes as f64);
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
        // Burn CPU for at least 100ms of wall-clock time so we accumulate
        // multiple clock ticks at 100Hz granularity (1 tick = 10ms).
        let deadline = Instant::now() + std::time::Duration::from_millis(100);
        let mut x: u64 = 0;
        let mut i: u64 = 0;
        while Instant::now() < deadline {
            x = std::hint::black_box(x).wrapping_add(std::hint::black_box(i));
            i = i.wrapping_add(1);
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

    /// Verifies parse_smaps_rollup with realistic synthetic content.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_smaps_rollup_synthetic() {
        let contents = "\
00100000-ff709000 ---p 00000000 00:00 0         [rollup]
Rss:                 884 kB
Pss:                 385 kB
Pss_Dirty:            68 kB
Pss_Anon:            301 kB
Pss_File:             80 kB
Pss_Shmem:             4 kB
Shared_Clean:        696 kB
Shared_Dirty:          0 kB
Private_Clean:       120 kB
Private_Dirty:        68 kB
Referenced:          884 kB
Anonymous:            68 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:              385 kB";

        let parsed = parse_smaps_rollup(contents, 42).expect("should parse synthetic smaps_rollup");
        assert_eq!(parsed.rss_bytes, 884 * 1024);
        assert_eq!(parsed.pss_bytes, 385 * 1024);
        assert_eq!(parsed.pss_anon_bytes, 301 * 1024);
        assert_eq!(parsed.pss_file_bytes, 80 * 1024);
        assert_eq!(parsed.pss_shmem_bytes, 4 * 1024);
        assert_eq!(parsed.swap_bytes, 0);
        assert_eq!(parsed.private_dirty_bytes, 68 * 1024);
        assert_eq!(parsed.shared_clean_bytes, 696 * 1024);
    }

    /// Verifies that unknown fields are silently ignored.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_smaps_rollup_unknown_fields() {
        let contents = "\
00100000-ff709000 ---p 00000000 00:00 0         [rollup]
Rss:                 100 kB
Pss:                  50 kB
FutureNewField:       99 kB";

        let parsed =
            parse_smaps_rollup(contents, 1).expect("unknown fields should not cause errors");
        assert_eq!(parsed.rss_bytes, 100 * 1024);
        assert_eq!(parsed.pss_bytes, 50 * 1024);
    }

    /// Verifies that a minimal smaps_rollup with only a header produces all-zero defaults.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_smaps_rollup_header_only() {
        let contents = "00100000-ff709000 ---p 00000000 00:00 0         [rollup]\n";
        let parsed =
            parse_smaps_rollup(contents, 1).expect("header-only should return defaults");
        assert_eq!(parsed.rss_bytes, 0);
        assert_eq!(parsed.pss_bytes, 0);
        assert_eq!(parsed.swap_bytes, 0);
    }

    /// Verifies that malformed smaps_rollup lines produce errors.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_smaps_rollup_malformed() {
        // Missing kB suffix
        let contents = "\
00100000-ff709000 ---p 00000000 00:00 0         [rollup]
Rss:                 884 MB";
        assert!(parse_smaps_rollup(contents, 1).is_err());

        // Non-numeric value
        let contents = "\
00100000-ff709000 ---p 00000000 00:00 0         [rollup]
Rss:                 abc kB";
        assert!(parse_smaps_rollup(contents, 1).is_err());
    }

    /// Verifies live smaps_rollup collection produces sane values.
    #[cfg(target_os = "linux")]
    #[test]
    fn collect_linux_smaps_rollup_for_self() {
        let own_pid = std::process::id();
        let smaps_path = format!("/proc/{own_pid}/smaps_rollup");

        // Skip test if smaps_rollup is not available on this kernel.
        if std::fs::metadata(&smaps_path).is_err() {
            eprintln!("skipping: smaps_rollup not available");
            return;
        }

        let pid = Pid::from_u32(own_pid, "self");
        let mut collector = ProcessMetricsCollector::new(MetricsConfig::default(), vec![pid]);
        let mut metrics = ProcessMetrics::default();

        collector
            .collect_process_metrics(pid, &mut metrics)
            .expect("should collect metrics for our own process");

        // PSS should be nonzero for any running process.
        assert!(
            metrics.pss_bytes > 0,
            "expected nonzero PSS, got {}",
            metrics.pss_bytes
        );

        // PSS <= RSS always holds (proportional accounting can only reduce, not inflate).
        assert!(
            metrics.pss_bytes <= metrics.physical_memory_bytes,
            "PSS ({}) should not exceed RSS ({})",
            metrics.pss_bytes,
            metrics.physical_memory_bytes
        );

        // Pss_Anon should be nonzero (we have heap allocations).
        assert!(
            metrics.pss_anon_bytes > 0,
            "expected nonzero PSS_Anon, got {}",
            metrics.pss_anon_bytes
        );
    }
}
