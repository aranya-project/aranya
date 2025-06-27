use std::{
    env, io, mem,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context as _, Result};
use aranya_client::{aqc::AqcPeerChannel, client::Client, Error, SyncPeerConfig, TeamConfig};
use aranya_daemon_api::{ChanOp, DeviceId, KeyBundle, NetIdentifier, Role};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use buggy::BugExt;
use bytes::Bytes;
#[cfg(target_os = "macos")]
use libc::{c_int, c_void, pid_t, proc_pidinfo, proc_taskinfo, PROC_PIDTASKINFO};
use libc::{getrusage, rusage, RUSAGE_SELF};
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
use tempfile::TempDir;
use tokio::{
    fs,
    process::{Child, Command},
    time::sleep,
};
use tracing::{debug, info, warn, Metadata};
use tracing_subscriber::{
    layer::{Context, Filter},
    prelude::*,
    EnvFilter,
};
use url::Url;

/// Configuration for metrics collection and exporting
#[derive(Debug)]
struct MetricsConfig {
    /// How often to poll for metrics
    pub collection_interval: Duration,

    /// Prometheus push gateway URL (if we're using a push gateway)
    pub push_gateway_url: Option<String>,
    /// How often to push data to the push gateway
    pub push_interval: Duration,
    /// Job name for the current push gateway
    pub job_name: String,

    /// HTTP address to listen to (if we're using a scrape endpoint)
    pub http_listen_addr: Option<SocketAddr>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            // poll 4 times a second
            collection_interval: Duration::from_millis(100),

            push_gateway_url: Some("http://localhost:9091".to_string()),
            push_interval: Duration::from_secs(1),
            job_name: format!(
                "aranya_demo_{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("We're past the Unix Epoch")
                    .as_secs()
            ),

            http_listen_addr: None,
        }
    }
}

/// Collector for process metrics, uses native APIs when possible.
#[derive(Debug)]
struct ProcessMetricsCollector {
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
    fn new(config: MetricsConfig, child_pids: Vec<u32>) -> Self {
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

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn collect_process_metrics(&self, pid: u32, metrics: &mut AggregatedMetrics) -> Result<()> {
        Err(anyhow!("Unsupported target_os!"))
    }

    #[cfg(target_os = "macos")]
    fn collect_native_macos_metrics(
        &self,
        pid: u32,
        process_metrics: &mut SingleProcessMetrics,
    ) -> Result<()> {
        // SAFETY: This has no alignment requirements, so mem::zeroed is safe.
        let mut task_info = unsafe { mem::zeroed::<proc_taskinfo>() };

        #[allow(clippy::cast_possible_wrap)]
        let pid = pid as pid_t;

        #[allow(clippy::cast_possible_wrap)]
        // SAFETY: We should have a valid PID, as well as buffer.
        let result = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDTASKINFO,
                0,
                &raw mut task_info as *mut c_void,
                size_of::<proc_taskinfo>() as c_int,
            )
        };

        // NOTE: -1 means error, otherwise it returns the number of bytes obtained.
        if result < 0 {
            return Err(io::Error::from_raw_os_error(result).into());
        }

        #[allow(clippy::cast_sign_loss)]
        if result as usize != size_of::<proc_taskinfo>() {
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
    fn collect_rusage_metrics(&self, process_metrics: &mut SingleProcessMetrics) -> Result<()> {
        // SAFETY: This has no alignment requirements so mem::zeroed is safe for all variants.
        let mut usage = unsafe { mem::zeroed::<rusage>() };
        // SAFETY: The above is safe and we're passing a valid pointer.
        let result = unsafe { getrusage(RUSAGE_SELF, &raw mut usage) };

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

    // TODO: inline as a closure?
    async fn start_collection_loop(&mut self) -> Result<()> {
        let mut interval = tokio::time::interval(self.config.collection_interval);

        loop {
            interval.tick().await;
            if let Err(e) = self.collect_metrics() {
                warn!("Failed to collect metrics: {e}");
            }
        }
    }
}

fn format_push_gateway_url(base_url: &str, job_name: &str) -> String {
    match Url::parse(base_url) {
        Ok(mut url) => {
            url.set_path(&format!("/metrics/job/{job_name}"));
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => {
            warn!("Failed to parse push gateway URL `{base_url}`");
            format!("http://localhost:9091/metrics/job/{job_name}")
        }
    }
}

fn setup_prometheus_exporter(config: &MetricsConfig) -> Result<()> {
    let mut builder = PrometheusBuilder::new();

    match (&config.push_gateway_url, &config.http_listen_addr) {
        (Some(base_url), _) => {
            let push_url = format_push_gateway_url(base_url, &config.job_name);
            info!("Setting up Prometheus push gateway node: {push_url}");
            builder =
                builder.with_push_gateway(push_url, config.push_interval, None, None, false)?;
        }
        (None, Some(listen_addr)) => {
            info!("Setting up Prometheus HTTP endpoint mode: {listen_addr}");
            builder = builder.with_http_listener(*listen_addr);
        }
        (None, None) => {
            return Err(anyhow!(
                "Must specify either push gateway URL or HTTP listen address"
            ));
        }
    }

    builder = builder.idle_timeout(MetricKindMask::ALL, Some(Duration::from_secs(300)));
    builder
        .install()
        .context("Failed to install Prometheus exporter")?;

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
    describe_gauge!("network_rx_bytes_total", "Total network bytes received");
    describe_gauge!("network_tx_bytes_total", "Total network bytes transmitted");
    describe_gauge!(
        "monitored_processes_count",
        "Number of processes being monitored"
    );

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

    describe_histogram!(
        "metrics_collection_duration_microseconds",
        "Time spent collecting metrics in microseconds"
    );
    describe_counter!(
        "demo_operations_total",
        "Total number of demo operations completed"
    );

    info!("Prometheus exporter configured successfully!");

    Ok(())
}

#[derive(Clone, Debug)]
struct DaemonPath(PathBuf);

#[derive(Debug)]
#[clippy::has_significant_drop]
struct Daemon {
    // NB: This has important drop side effects.
    proc: Child,
    _work_dir: PathBuf,
}

impl Daemon {
    async fn spawn(path: &DaemonPath, work_dir: &Path, cfg_path: &Path) -> Result<Self> {
        fs::create_dir_all(&work_dir).await?;

        let cfg_path = cfg_path.as_os_str().to_str().context("should be UTF-8")?;
        let mut cmd = Command::new(&path.0);
        cmd.kill_on_drop(true)
            .current_dir(work_dir)
            .args(["--config", cfg_path]);
        debug!(?cmd, "spawning daemon");
        let proc = cmd.spawn().context("unable to spawn daemon")?;
        Ok(Daemon {
            proc,
            _work_dir: work_dir.into(),
        })
    }

    fn pid(&self) -> Option<u32> {
        self.proc.id()
    }
}

/// An Aranya device.
struct ClientCtx {
    client: Client,
    aqc_addr: SocketAddr,
    pk: KeyBundle,
    id: DeviceId,
    // NB: These have important drop side effects.
    _work_dir: TempDir,
    daemon: Daemon,
}

impl ClientCtx {
    pub async fn new(team_name: &str, user_name: &str, daemon_path: &DaemonPath) -> Result<Self> {
        info!(team_name, user_name, "creating `ClientCtx`");

        let work_dir = TempDir::with_prefix(user_name)?;

        let daemon = {
            let work_dir = work_dir.path().join("daemon");
            fs::create_dir_all(&work_dir).await?;

            let cfg_path = work_dir.join("config.json");

            let runtime_dir = work_dir.join("run");
            let state_dir = work_dir.join("state");
            let cache_dir = work_dir.join("cache");
            let logs_dir = work_dir.join("logs");
            let config_dir = work_dir.join("config");
            for dir in &[&runtime_dir, &state_dir, &cache_dir, &logs_dir, &config_dir] {
                fs::create_dir_all(dir)
                    .await
                    .with_context(|| format!("unable to create directory: {}", dir.display()))?;
            }

            let buf = format!(
                r#"
                name: "daemon"
                runtime_dir: {runtime_dir:?}
                state_dir: {state_dir:?}
                cache_dir: {cache_dir:?}
                logs_dir: {logs_dir:?}
                config_dir: {config_dir:?}
                sync_addr: "localhost:0"
                "#
            );
            fs::write(&cfg_path, buf).await?;

            Daemon::spawn(daemon_path, &work_dir, &cfg_path).await?
        };

        // The path that the daemon will listen on.
        let uds_sock = work_dir.path().join("daemon").join("run").join("uds.sock");

        // Give the daemon time to start up and write its public key.
        sleep(Duration::from_millis(100)).await;

        let any_addr = Addr::from((Ipv4Addr::LOCALHOST, 0));

        let mut client = (|| {
            Client::builder()
                .with_daemon_uds_path(&uds_sock)
                .with_daemon_aqc_addr(&any_addr)
                .connect()
        })
        .retry(ExponentialBuilder::default())
        .await
        .context("unable to initialize client")?;

        let aqc_server_addr = client.aqc().server_addr().context("exepcted server addr")?;
        let pk = client
            .get_key_bundle()
            .await
            .context("expected key bundle")?;
        let id = client.get_device_id().await.context("expected device id")?;

        Ok(Self {
            client,
            aqc_addr: aqc_server_addr,
            pk,
            id,
            _work_dir: work_dir,
            daemon,
        })
    }

    async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.local_addr().await?)
    }
}

struct DemoFilter {
    env_filter: EnvFilter,
}

impl<S> Filter<S> for DemoFilter {
    fn enabled(&self, metadata: &Metadata<'_>, context: &Context<'_, S>) -> bool {
        if metadata.target().starts_with(module_path!()) {
            true
        } else {
            self.env_filter.enabled(metadata, context.clone())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = DemoFilter {
        env_filter: EnvFilter::try_from_env("ARANYA_EXAMPLE")
            .unwrap_or_else(|_| EnvFilter::new("off")),
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_file(false)
                .with_target(false)
                .compact()
                .with_filter(filter),
        )
        .init();

    info!("Starting Aranya Example with Metrics Collection");

    let mut metrics_config = MetricsConfig::default();

    if let Ok(push_gateway) = env::var("PROMETHEUS_PUSH_GATEAWAY") {
        metrics_config.push_gateway_url = Some(push_gateway);
        metrics_config.http_listen_addr = None;
    } else if let Ok(listen_addr) = env::var("PROMETHEUS_LISTEN_ADDR") {
        metrics_config.push_gateway_url = None;
        metrics_config.http_listen_addr = Some(
            listen_addr
                .parse()
                .context("unable to convert `PROMETHEUS_LISTEN_ADDR`")?,
        );
    }

    if let Ok(job_name) = env::var("PROMETHEUS_JOB_NAME") {
        metrics_config.job_name = job_name;
    }

    if let Ok(collection_interval) = env::var("COLLECTION_INTERVAL") {
        if let Ok(collection_interval) = collection_interval.parse::<u64>() {
            metrics_config.collection_interval = Duration::from_millis(collection_interval);
        }
    }

    setup_prometheus_exporter(&metrics_config)?;

    info!("Phase 1: Setting up daemons");
    let (daemon_pids, demo_context) = setup_demo().await?;

    // TODO(nikki): sleep a tiny bit so the daemons can spin up?

    info!(
        "Phase 2: Starting metrics collection for PIDs: {:?}",
        daemon_pids.clone().push(std::process::id())
    );
    let mut metrics_collector = ProcessMetricsCollector::new(metrics_config, daemon_pids);

    info!("Phase 3: Running demo with real-time metrics collection");
    let metrics_handle =
        tokio::spawn(async move { metrics_collector.start_collection_loop().await });

    let demo_result = run_demo_body(demo_context).await;

    // Wait a moment so we can make sure we capture all metrics state
    sleep(Duration::from_millis(500)).await;

    metrics_handle.abort();

    match demo_result {
        Ok(()) => {
            info!("Demo completed successfully");
            counter!("demo_operations_total", "operation" => "success").increment(1);
        }
        Err(ref e) => {
            warn!("Demo failed with error: {e}");
            counter!("demo_operations_total", "operation" => "failure").increment(1);
        }
    }

    demo_result
}

struct DemoContext {
    owner: ClientCtx,
    admin: ClientCtx,
    operator: ClientCtx,
    membera: ClientCtx,
    memberb: ClientCtx,
}

async fn setup_demo() -> Result<(Vec<u32>, DemoContext)> {
    let daemon_path = {
        let mut args = env::args();
        args.next(); // skip executable name
        let exe = args.next().context("missing `daemon` executable path")?;
        DaemonPath(PathBuf::from(exe))
    };

    // TODO(nikki): move TeamId here?

    let team_name = "rust_example";
    const CLIENT_NAMES: [&str; 5] = ["owner", "admin", "operator", "member_a", "member_b"];
    let mut contexts: [Option<ClientCtx>; CLIENT_NAMES.len()] = Default::default();
    let mut daemon_pids: Vec<u32> = Vec::with_capacity(CLIENT_NAMES.len());

    for (i, &user_name) in CLIENT_NAMES.iter().enumerate() {
        let ctx = ClientCtx::new(team_name, user_name, &daemon_path).await?;

        if let Some(pid) = ctx.daemon.pid() {
            daemon_pids.push(pid);
        } else {
            warn!("Daemon PID not available for user: {user_name}");
        }

        contexts[i] = Some(ctx);
    }

    // If this panics, we have bigger things to worry about.
    let [owner, admin, operator, membera, memberb] =
        contexts.map(|ctx| ctx.expect("All contexts should have been initialized"));

    Ok((
        daemon_pids,
        DemoContext {
            owner,
            admin,
            operator,
            membera,
            memberb,
        },
    ))
}

async fn run_demo_body(mut ctx: DemoContext) -> Result<()> {
    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;

    // Create a team.
    info!("creating team");
    let cfg = TeamConfig::builder().build()?;
    let team_id = ctx
        .owner
        .client
        .create_team(cfg)
        .await
        .context("expected to create team")?;
    info!(%team_id);

    // get sync addresses.
    let owner_addr = ctx.owner.aranya_local_addr().await?;
    let admin_addr = ctx.admin.aranya_local_addr().await?;
    let operator_addr = ctx.operator.aranya_local_addr().await?;
    let membera_addr = ctx.membera.aranya_local_addr().await?;
    let memberb_addr = ctx.memberb.aranya_local_addr().await?;

    // get aqc addresses.
    debug!(?ctx.membera.aqc_addr, ?ctx.memberb.aqc_addr);

    // setup sync peers.
    let mut owner_team = ctx.owner.client.team(team_id);
    let mut admin_team = ctx.admin.client.team(team_id);
    let mut operator_team = ctx.operator.client.team(team_id);
    let mut membera_team = ctx.membera.client.team(team_id);
    let mut memberb_team = ctx.memberb.client.team(team_id);

    info!("adding admin to team");
    owner_team.add_device_to_team(ctx.admin.pk).await?;
    owner_team.assign_role(ctx.admin.id, Role::Admin).await?;

    sleep(sleep_interval).await;

    info!("adding operator to team");
    owner_team.add_device_to_team(ctx.operator.pk).await?;

    sleep(sleep_interval).await;

    // Admin tries to assign a role
    match admin_team
        .assign_role(ctx.operator.id, Role::Operator)
        .await
    {
        Ok(()) => bail!("expected role assignment to fail"),
        Err(Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected error: {err:?}"),
    }

    // Admin syncs with the Owner peer and retries the role
    // assignment command
    admin_team.sync_now(owner_addr.into(), None).await?;

    sleep(sleep_interval).await;

    info!("assigning role");
    admin_team
        .assign_role(ctx.operator.id, Role::Operator)
        .await?;

    info!("adding sync peers");
    owner_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    owner_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    owner_team
        .add_sync_peer(membera_addr.into(), sync_cfg.clone())
        .await?;

    admin_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    admin_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    admin_team
        .add_sync_peer(membera_addr.into(), sync_cfg.clone())
        .await?;

    operator_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    operator_team
        .add_sync_peer(membera_addr.into(), sync_cfg.clone())
        .await?;

    membera_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    membera_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    membera_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    membera_team
        .add_sync_peer(memberb_addr.into(), sync_cfg.clone())
        .await?;

    memberb_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    memberb_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    memberb_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    memberb_team
        .add_sync_peer(membera_addr.into(), sync_cfg)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add membera to team.
    info!("adding membera to team");
    operator_team
        .add_device_to_team(ctx.membera.pk.clone())
        .await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator_team.add_device_to_team(ctx.memberb.pk).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    info!("assigning aqc net identifiers");
    operator_team
        .assign_aqc_net_identifier(
            ctx.membera.id,
            NetIdentifier(ctx.membera.aqc_addr.to_string()),
        )
        .await?;
    operator_team
        .assign_aqc_net_identifier(
            ctx.memberb.id,
            NetIdentifier(ctx.memberb.aqc_addr.to_string()),
        )
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // fact database queries
    let mut queries = ctx.membera.client.queries(team_id);
    let devices = queries.devices_on_team().await?;
    info!("membera devices on team: {:?}", devices.iter().count());
    let role = queries.device_role(ctx.membera.id).await?;
    info!("membera role: {:?}", role);
    let keybundle = queries.device_keybundle(ctx.membera.id).await?;
    info!("membera keybundle: {:?}", keybundle);
    let queried_membera_net_ident = queries.aqc_net_identifier(ctx.membera.id).await?;
    info!(
        "membera queried_membera_net_ident: {:?}",
        queried_membera_net_ident
    );
    let queried_memberb_net_ident = queries.aqc_net_identifier(ctx.memberb.id).await?;
    info!(
        "memberb queried_memberb_net_ident: {:?}",
        queried_memberb_net_ident
    );

    // wait for syncing.
    sleep(sleep_interval).await;

    info!("demo aqc functionality");
    info!("creating aqc label");
    let label3 = operator_team.create_label("label3".to_string()).await?;
    let op = ChanOp::SendRecv;
    info!("assigning label to membera");
    operator_team
        .assign_label(ctx.membera.id, label3, op)
        .await?;
    info!("assigning label to memberb");
    operator_team
        .assign_label(ctx.memberb.id, label3, op)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // membera creates a bidirectional channel.
    info!("membera creating acq bidi channel");
    // Prepare arguments that need to be captured by the async move block
    let memberb_net_identifier = NetIdentifier(ctx.memberb.aqc_addr.to_string());

    let create_handle = tokio::spawn(async move {
        let channel_result = ctx
            .membera
            .client
            .aqc()
            .create_bidi_channel(team_id, memberb_net_identifier, label3)
            .await;
        (channel_result, ctx.membera) // Return membera along with the result
    });

    // memberb receives a bidirectional channel.
    info!("memberb receiving acq bidi channel");
    let AqcPeerChannel::Bidi(mut received_aqc_chan) =
        ctx.memberb.client.aqc().receive_channel().await?
    else {
        bail!("expected a bidirectional channel");
    };

    // Now await the completion of membera's channel creation
    let (created_aqc_chan_result, membera_returned) = create_handle
        .await
        .context("Task for membera creating bidi channel panicked")?;
    ctx.membera = membera_returned; // Assign the moved membera back
    let mut created_aqc_chan =
        created_aqc_chan_result.context("Membera failed to create bidi channel")?;

    // membera creates a new stream on the channel.
    info!("membera creating aqc bidi stream");
    let mut bidi1 = created_aqc_chan.create_bidi_stream().await?;

    // membera sends data via the aqc stream.
    info!("membera sending aqc data");
    let msg = Bytes::from_static(b"hello");
    bidi1.send(msg.clone()).await?;

    // memberb receives channel stream created by membera.
    info!("memberb receiving aqc bidi stream");
    let mut peer2 = received_aqc_chan
        .receive_stream()
        .await
        .assume("stream not received")?;

    // memberb receives data from stream.
    info!("memberb receiving acq data");
    let bytes = peer2.receive().await?.assume("no data received")?;
    assert_eq!(bytes, msg);

    info!("revoking label from membera");
    operator_team.revoke_label(ctx.membera.id, label3).await?;
    info!("revoking label from memberb");
    operator_team.revoke_label(ctx.memberb.id, label3).await?;
    info!("deleting label");
    admin_team.delete_label(label3).await?;

    info!("completed aqc demo");

    info!("completed example Aranya application");

    // sleep a moment so we can get a stable final state for all daemons
    sleep(Duration::from_millis(500)).await;

    Ok(())
}
