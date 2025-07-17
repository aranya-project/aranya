//! Configuration for an exporter to send data to a [Prometheus] backend or a [`pushgateway`].
//!
//! [Prometheus]: https://prometheus.io/
//! [`pushgateway`]: https://github.com/prometheus/pushgateway

use std::{net::SocketAddr, num::NonZeroU32, path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;
use serde::Deserialize;
use tracing::info;

/// Configuration info for the Prometheus exporter.
///
/// This includes:
/// * The current mode (either exporting to Prometheus via Unix Domain Socket or normal HTTP, or
///   using a pushgateway that syncs with Prometheus)
/// * The timeout for a metric before it stops being logged. For long running tasks, this is ideal
///   to tune since it will give a nice cutoff after a specific task might have finished.
/// * A whitelist of addresses allowed to connect to the exporter
/// * The list of quantiles (0.0, 0.5, 0.9, 0.95, 0.99, 0.999, and 1.0) used when rendering
///   histograms
/// * The number and size of buckets, which allow for greater flexibility in Prometheus to derive
///   quantiles
/// * How often the upkeep task runs, which cleans out metrics that Prometheus has already scraped
/// * A set of global labels that can be applied to all metrics
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PrometheusConfig {
    /// The current mode that the Prometheus exporter is operating as.
    mode: PrometheusMode,

    /// Sets the idle timeout for metrics.
    idle_timeout: (MetricsKindMask, Option<Duration>),
    /// Sets whether a unit suffix is added to metric names.
    enable_unit_suffix: bool,

    /// Allows only certain addresses to access the scrape endpoint.
    allowed_addresses: Option<Vec<String>>,
    /// Sets the number of quantiles when rendering histograms.
    quantiles: Option<Vec<f64>>,
    /// Sets the buckets to use when rendering histograms.
    buckets: Option<Vec<f64>>,
    /// Sets the "width" of each bucket when using summaries.
    bucket_duration: Option<Duration>,
    /// Sets the number of buckets kept in memory at one time.
    bucket_count: Option<NonZeroU32>,
    /// Sets the interval that the upkeep task runs at.
    upkeep_timeout: Option<Duration>,
    /// Sets global labels that are applied to all metrics.
    global_labels: Option<Vec<(String, String)>>,
}

impl PrometheusConfig {
    /// Configures and installs the exporter for Prometheus using the provided config info.
    pub(super) fn install(&self, config: &super::MetricsConfig) -> Result<()> {
        let mut builder = PrometheusBuilder::new();

        match &self.mode {
            PrometheusMode::HttpListener { addr } => {
                info!("Setting up Prometheus HTTP listener: {addr}");
                builder = builder.with_http_listener(*addr);
            }
            PrometheusMode::UdsListener { addr } => {
                info!("Setting up Prometheus UDS listener: {addr:?}");
                builder = builder.with_http_uds_listener(addr)
            }
            PrometheusMode::PushGateway {
                endpoint,
                username,
                password,
                use_http_post_method,
            } => {
                let endpoint = endpoint
                    .parse::<http::Uri>()
                    .map(|_| endpoint.clone())
                    .unwrap_or(format!(
                        "http://localhost:9091/metrics/job/{}",
                        &config.job_name
                    ));

                info!("Setting up Prometheus push gateway: {endpoint}");
                builder = builder.with_push_gateway(
                    endpoint,
                    config.interval,
                    username.clone(),
                    password.clone(),
                    *use_http_post_method,
                )?
            }
        }

        let (mask, timeout) = &self.idle_timeout;
        builder = builder
            .idle_timeout(MetricKindMask::from(mask.clone()), *timeout)
            .set_enable_unit_suffix(self.enable_unit_suffix);

        if let Some(addresses) = &self.allowed_addresses {
            for address in addresses {
                builder = builder.add_allowed_address(address)?;
            }
        }

        if let Some(quantiles) = &self.quantiles {
            builder = builder.set_quantiles(quantiles)?;
        }

        if let Some(values) = &self.buckets {
            builder = builder.set_buckets(values)?;
        }

        if let Some(value) = self.bucket_duration {
            builder = builder.set_bucket_duration(value)?;
        }

        if let Some(count) = self.bucket_count {
            builder = builder.set_bucket_count(count);
        }

        if let Some(timeout) = self.upkeep_timeout {
            builder = builder.upkeep_timeout(timeout);
        }

        if let Some(labels) = &self.global_labels {
            for (key, value) in labels {
                builder = builder.add_global_label(key, value);
            }
        }

        builder
            .install()
            .context("Failed to install Prometheus exporter")?;

        Ok(())
    }
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            mode: PrometheusMode::PushGateway {
                endpoint: SocketAddr::from(([127, 0, 0, 1], 9091)).to_string(),
                username: None,
                password: None,
                use_http_post_method: false,
            },

            idle_timeout: (MetricsKindMask::All, Some(Duration::from_millis(100))),
            enable_unit_suffix: false,

            allowed_addresses: None,
            quantiles: None,
            buckets: None,
            bucket_duration: None,
            bucket_count: None,
            upkeep_timeout: None,
            global_labels: None,
        }
    }
}

/// Defines the mode that the Prometheus exporter operates on (listener/gateway).
#[derive(Debug, Clone, Deserialize)]
#[allow(clippy::missing_docs_in_private_items)]
enum PrometheusMode {
    /// Creates an HTTP listener using an HTTP address to scrape from.
    HttpListener { addr: SocketAddr },
    /// Creates an HTTP listener using a UDS address to scrape from.
    UdsListener { addr: PathBuf },
    /// Tells the exporter to periodically push data to a push gateway.
    PushGateway {
        endpoint: String,
        username: Option<String>,
        password: Option<String>,
        use_http_post_method: bool,
    },
}

#[derive(Debug, Clone, Deserialize)]
enum MetricsKindMask {
    None = 0,
    Counter = 1,
    Gauge = 2,
    Histogram = 4,
    All = 7,
}

impl From<MetricsKindMask> for MetricKindMask {
    fn from(value: MetricsKindMask) -> Self {
        match value {
            MetricsKindMask::None => MetricKindMask::NONE,
            MetricsKindMask::Counter => MetricKindMask::COUNTER,
            MetricsKindMask::Gauge => MetricKindMask::GAUGE,
            MetricsKindMask::Histogram => MetricKindMask::HISTOGRAM,
            MetricsKindMask::All => MetricKindMask::ALL,
        }
    }
}
