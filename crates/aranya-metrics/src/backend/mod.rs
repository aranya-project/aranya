//! This module contains all the backend code needed to export metrics to a remote server, as well
//! as various other configuration parameters that handle things such as logging to the console.
//!
//! The currently supported backends are:
//! * [Prometheus], using either [Prometheus](https://prometheus.io/) scraping, or a `pushgateway`.
//! * [Datadog] using [DogStatsD], provided as a service as part of a Datadog Agent.
//! * [TCP Server], used for more advanced metrics collection and processing, sent using [`protobuf`].
//!
//! [Prometheus]: https://docs.rs/metrics-exporter-prometheus/
//! [DataDog]: https://docs.rs/metrics-exporter-dogstatsd/
//! [DogStatsD]: https://docs.datadoghq.com/developers/dogstatsd/
//! [TCP Server]: https://docs.rs/metrics-exporter-tcp/
//! [`protobuf`]: https://protobuf.dev/
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;

pub mod datadog;
pub mod prometheus;
pub mod tcp_server;

/// Sets the granularity of metrics reported using [`tracing::debug!()`] each [`interval`].
///
/// [`interval`]: MetricsConfig::interval
/// [`tracing::debug!()`]: tracing::debug
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum DebugLogType {
    /// Turns off metrics logging for the current run.
    None,
    /// Reports the total aggregated metrics for the current tick.
    #[default]
    Total,
    /// Reports the metrics for individual processes (and the total) for the current tick.
    PerProcess,
}

/// Configuration info used to report metrics to a remote server, as well as logging metrics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// The method used to export metrics to a remote server.
    pub mode: MetricsMode,
    /// How often to forward data to the remote server. See [`MetricsMode`] for more information.
    pub interval: Duration,
    /// The current job name, used for filtering out metrics to the current run.
    pub job_name: String,
    /// Whether to log metrics to the console using [`tracing::debug!()`](tracing::debug).
    pub debug_logs: DebugLogType,
}

impl MetricsConfig {
    /// Sets up the selected exporter using the provided configuration info.
    pub fn install(&self) -> Result<()> {
        match &self.mode {
            MetricsMode::Prometheus(prometheus) => {
                prometheus.install(self)?;
            }
            MetricsMode::DataDog(datadog) => {
                datadog.install(self)?;
            }
            MetricsMode::TcpServer(tcp_server) => {
                tcp_server.install()?;
            }
            MetricsMode::None => {}
        }

        Ok(())
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            mode: MetricsMode::default(),
            interval: Duration::from_millis(10),
            job_name: format!(
                "aranya_demo_{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("We're past the Unix Epoch")
                    .as_secs()
            ),
            debug_logs: DebugLogType::default(),
        }
    }
}

/// Defines which remote backend to configure and send metrics to.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub enum MetricsMode {
    /// Uses the Prometheus exporter to collect data. Depending on the mode, Prometheus will either
    /// scrape data every [`interval`], or has data pushed to it every [`interval`].
    ///
    /// Note that this determines how granular the exported data is, as Prometheus treats each
    /// scrape as a single snapshot in time.
    ///
    /// [`interval`]: MetricsConfig::interval
    Prometheus(prometheus::PrometheusConfig),

    /// Uses the DogStatsD exporter to collect data. Note that depending on [`interval`], this may
    /// increase network processing overhead.
    ///
    /// [`interval`]: MetricsConfig::interval
    DataDog(datadog::DataDogConfig),

    /// Configures a TCP server that listens for connections and streams metrics using [`protobuf`].
    ///
    /// [`protobuf`]: https://protobuf.dev/
    TcpServer(tcp_server::TcpConfig),

    /// Disables exporting metrics to a remote backend. Note that you can still report metrics using
    /// [`debug_logs`](MetricsConfig::debug_logs).
    #[default]
    None,
}
