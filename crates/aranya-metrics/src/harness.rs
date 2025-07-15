use std::{io, mem, time::Instant};

use anyhow::{anyhow, Result};
use metrics::{describe_gauge, describe_histogram, gauge, histogram};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
use tracing::{debug, warn};

use crate::{export::DebugLogType, MetricsConfig};

/// Collector for process metrics, uses native APIs when possible.
#[derive(Debug)]
pub struct ProcessMetricsCollector {
    /// Config options for the current run
    config: MetricsConfig,
    /// System handle for fallback metrics
    system: System,
    /// All child process PIDs for tracking
    child_pids: Vec<u32>,
    /// Collection start time for rate calculations
    _start_time: Instant,
    /// Previous metrics for rate calculations
    previous_metrics: Option<AggregatedMetrics>,
    /// Total cumulative metrics for this run
    total_metrics: AggregatedMetrics,
}

#[derive(Debug)]
struct AggregatedMetrics {
    /// ~The moment we measured these metrics
    timestamp: Instant,
    total_cpu_user_time_us: u64,
    total_cpu_system_time_us: u64,
    total_memory_bytes: u64,
    total_disk_read_bytes: u64,
    total_disk_write_bytes: u64,
    // TODO(nikki): hook the TCP/QUIC syncer with a metrics macro.
    //total_network_rx_bytes: u64,
    //total_network_tx_bytes: u64,
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

#[derive(Debug, Default)]
struct SingleProcessMetrics {
    cpu_user_time_us: u64,
    cpu_system_time_us: u64,
    memory_bytes: u64,
    disk_read_bytes: u64,
    disk_write_bytes: u64,
}

impl ProcessMetricsCollector {
    /// Create a new instance to collect process metrics.
    pub fn new(config: MetricsConfig, child_pids: Vec<u32>) -> Self {
        Self::register_metrics();

        let system = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing().with_disk_usage()),
        );

        Self {
            config,
            system,
            child_pids,
            _start_time: Instant::now(),
            previous_metrics: None,
            total_metrics: AggregatedMetrics::default(),
        }
    }

    fn register_metrics() {
        // All our accumulated totals across the run
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

        // All our delta metrics since last tick
        describe_gauge!(
            "cpu_user_utilization_rate",
            "User CPU utilization since last tick"
        );
        describe_gauge!(
            "cpu_system_utilization_rate",
            "System CPU utilization since last tick"
        );
        describe_gauge!(
            "cpu_total_utilization_rate",
            "Total CPU utilization since last tick"
        );
        describe_gauge!(
            "memory_allocation_rate",
            "Amount of allocated memory since last tick"
        );
        describe_gauge!(
            "disk_read_bytes_rate",
            "Number of bytes read since last tick"
        );
        describe_gauge!(
            "disk_write_bytes_rate",
            "Number of bytes written since last tick"
        );

        // Other miscellaneous helpful datapoints
        describe_gauge!(
            "monitored_processes_count",
            "Number of processes being monitored"
        );
        describe_histogram!(
            "metrics_collection_duration_microseconds",
            "Time spent collecting metrics in microseconds"
        );
    }

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

        match self.config.debug_logs {
            DebugLogType::None => (),
            _ => debug!("Total Metrics: {:?}", self.total_metrics),
        }

        // Push those values to our backend
        self.update_prometheus_metrics(&current)?;

        // Save those metrics so we have that delta for the next tick
        self.previous_metrics = Some(current);

        // Record how long it took us to actually collect those metrics
        #[allow(clippy::cast_precision_loss)]
        histogram!("metrics_collection_duration_microseconds")
            .record(collection_start.elapsed().as_micros() as f64);

        Ok(())
    }

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

        // Collect metrics for the current process
        self.collect_process_metrics(std::process::id(), &mut metrics)?;

        for &pid in self.child_pids.clone().iter() {
            if let Err(e) = self.collect_process_metrics(pid, &mut metrics) {
                warn!("Failed to collect metrics for child PID {pid}: {e}");
            }
        }

        metrics.process_count = 1 + self.child_pids.len();

        Ok(metrics)
    }

    #[cfg(target_os = "macos")]
    fn collect_process_metrics(&mut self, pid: u32, metrics: &mut AggregatedMetrics) -> Result<()> {
        // First, let's collect metrics for the individual process.
        let mut process_metrics = SingleProcessMetrics::default();

        if self
            .collect_native_macos_metrics(pid, &mut process_metrics)
            .is_err()
        {
            // If we're trying to track our own process, we can fallback to rusage.
            if pid == std::process::id() {
                self.collect_rusage_metrics(&mut process_metrics)?;
            }
        }

        // Always fallback to sysinfo for disk metrics.
        self.collect_sysinfo_disk_metrics(pid, &mut process_metrics)?;

        // Aggregate this process's metrics towards the total.
        metrics.total_cpu_user_time_us += process_metrics.cpu_user_time_us;
        metrics.total_cpu_system_time_us += process_metrics.cpu_system_time_us;
        metrics.total_memory_bytes += process_metrics.memory_bytes;
        metrics.total_disk_read_bytes += process_metrics.disk_read_bytes;
        metrics.total_disk_write_bytes += process_metrics.disk_write_bytes;

        if let DebugLogType::PerProcess = self.config.debug_logs {
            debug!("PID {pid} Process Metrics: {process_metrics:?}");
        }

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    #[allow(dead_code)]
    fn collect_process_metrics(&self, _pid: u32, _metrics: &mut AggregatedMetrics) -> Result<()> {
        Err(anyhow!("Unsupported target_os!"))
    }

    #[cfg(target_os = "macos")]
    fn collect_native_macos_metrics(
        &self,
        pid: u32,
        process_metrics: &mut SingleProcessMetrics,
    ) -> Result<()> {
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

    #[allow(clippy::cast_sign_loss)]
    #[allow(dead_code)]
    fn collect_rusage_metrics(&self, process_metrics: &mut SingleProcessMetrics) -> Result<()> {
        // SAFETY: This has no alignment requirements so mem::zeroed is safe for all variants.
        let mut usage = unsafe { mem::zeroed::<libc::rusage>() };
        // SAFETY: The above is safe and we're passing a valid pointer.
        let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) };

        if result < 0 {
            return Err(io::Error::from_raw_os_error(result))?;
        }

        process_metrics.cpu_user_time_us =
            (usage.ru_utime.tv_sec as u64 * 1_000_000) + usage.ru_utime.tv_usec as u64;
        process_metrics.cpu_system_time_us =
            (usage.ru_stime.tv_sec as u64 * 1_000_000) + usage.ru_stime.tv_usec as u64;

        // The max resident set size is bytes on MacOS and kilobytes on Linux/BSD. POSIX only really
        // guarantees the above two fields, so anything else is platform-dependent.
        process_metrics.memory_bytes = match cfg!(target_os = "macos") {
            true => usage.ru_maxrss as u64,
            false => usage.ru_maxrss as u64 * 1024,
        };

        // TODO(nikki): collect more metrics? There aren't guarantees here on most fields, but we
        // can get page faults and filesystem I/O count.
        Ok(())
    }

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

    fn update_prometheus_metrics(&self, current: &AggregatedMetrics) -> Result<()> {
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
            // TODO(nikki): not sure if we should report these here/in each process at the syncer site.
            //gauge!("network_rx_bytes_total").set(total.total_network_rx_bytes as f64);
            //gauge!("network_tx_bytes_total").set(total.total_network_tx_bytes as f64);
            gauge!("monitored_processes_count").set(total.process_count as f64);
        }

        // Update rate metrics if we have a previous timestep.
        if let Some(previous) = &self.previous_metrics {
            let time_delta = current
                .timestamp
                .duration_since(previous.timestamp)
                .as_secs_f64();

            #[allow(clippy::cast_precision_loss)]
            if time_delta > 0.0 {
                // proc_pidinfo returns cpu time since spinup, as well as "current" memory usage so
                // we need to get the delta since the previous tick.
                let cpu_user_rate = ((current.total_cpu_user_time_us as f64)
                    - (previous.total_cpu_user_time_us as f64))
                    / time_delta;
                let cpu_system_rate = ((current.total_cpu_system_time_us as f64)
                    - (previous.total_cpu_system_time_us as f64))
                    / time_delta;
                let memory_alloc_rate = ((current.total_memory_bytes as f64)
                    - (previous.total_memory_bytes as f64))
                    / time_delta;

                // sysinfo already gives us the bytes "since last refresh", so this is fine.
                let disk_read_rate = (current.total_disk_read_bytes as f64) / time_delta;
                let disk_write_rate = (current.total_disk_write_bytes as f64) / time_delta;

                gauge!("cpu_user_utilization_rate").set(cpu_user_rate);
                gauge!("cpu_system_utilization_rate").set(cpu_system_rate);
                gauge!("cpu_total_utilization_rate").set(cpu_user_rate + cpu_system_rate);
                gauge!("memory_allocation_rate").set(memory_alloc_rate);
                // TODO(nikki): standardize this on "per second", even if we tick more/less frequently?
                gauge!("disk_read_bytes_rate").set(disk_read_rate);
                gauge!("disk_write_bytes_rate").set(disk_write_rate);
            }
        }
        Ok(())
    }

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
