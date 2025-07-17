//! Configuration for an exporter to send data to [Datadog] using [`DogStatsD`]
//!
//! [Datadog]: https://www.datadoghq.com/
//! [`DogStatsD`]: https://docs.datadoghq.com/developers/dogstatsd/

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context as _, Result};
use metrics::Label;
use metrics_exporter_dogstatsd::DogStatsDBuilder;
use tracing::info;

/// Configuration info for the DogStatsD exporter.
///
/// This includes:
/// * The address of the Datadog Agent to connect to
/// * How long to try sending before metrics are dropped and the length of each payload trying to be
///   sent
/// * The aggregation mode used by the exporter to optimize what payloads are being sent
/// * Optional prefixes and additional labels that can be attached to metrics being sent
/// * Whether to enable additional telemetry, which lets the Datadog Agent see additional info about
///   how the exporter is performing
/// * Whether to use reservoir sampling to represent arbitrarily large data using a smaller array
/// * Whether to forward histograms as distributions, which allows the Datadog Agent to process the
///   data which allows for richer insights
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct DataDogConfig {
    // Current backend is always synchronous, so we don't bother with it here.
    /// The remote address to send metrics to (UDP or UDS).
    remote_addr: String,
    /// Write timeout for forwarding metrics.
    write_timeout: Duration,
    /// Max payload length for forwarding metrics.
    max_payload_len: Option<usize>,

    /// Defines the aggregation strategy used for sending data.
    mode: AggregationMode,

    /// Adds a prefix to all metrics sent using this exporter.
    global_prefix: Option<String>,
    /// Sets global labels that are applied to all metrics.
    global_labels: Option<Vec<(String, String)>>,

    /// Whether to enable telemetry for the exporter.
    telemetry: bool,
    /// Whether to enable histogram sampling, which uses a reservoir to sample an arbitrarily large
    /// number of inputs using a const sized array.
    histogram_sampling: Option<usize>,
    /// Defines whether to send histograms as distributions. Enabling this allows for richer support
    /// for aggregation and percentiles on the remote backend.
    histograms_as_distributions: bool,
}

impl Default for DataDogConfig {
    fn default() -> Self {
        Self {
            remote_addr: SocketAddr::from(([127, 0, 0, 1], 8125)).to_string(),
            write_timeout: Duration::from_secs(1),
            max_payload_len: None,

            mode: AggregationMode::Conservative,

            global_prefix: None,
            global_labels: None,

            telemetry: true,
            histogram_sampling: Some(1024),
            histograms_as_distributions: true,
        }
    }
}

impl DataDogConfig {
    /// Configures and installs the exporter for DogStatsD using the provided config info.
    pub(super) fn install(&self, config: &super::MetricsConfig) -> Result<()> {
        info!("Setting up DogStatsD exporter: {}", self.remote_addr);

        let mut builder = DogStatsDBuilder::default();

        builder = builder
            .with_remote_address(&self.remote_addr)
            .context("Failed to set remote address")?;

        builder = builder.with_write_timeout(self.write_timeout);

        if let Some(max_len) = self.max_payload_len {
            builder = builder
                .with_maximum_payload_length(max_len)
                .context("Failed to set maximum payload length")?;
        }

        match &self.mode {
            AggregationMode::Conservative => {
                builder = builder.with_aggregation_mode(AggregationMode::Conservative.into())
            }
            AggregationMode::Aggressive => {
                builder = builder.with_aggregation_mode(AggregationMode::Aggressive.into())
            }
        }
        builder = builder.with_flush_interval(config.interval);

        if let Some(prefix) = &self.global_prefix {
            builder = builder.set_global_prefix(prefix);
        }

        if let Some(labels) = &self.global_labels {
            let labels = labels
                .iter()
                .map(|(key, value)| Label::new(key.clone(), value.clone()))
                .collect();
            builder = builder.with_global_labels(labels);
        }

        builder = builder
            .with_telemetry(self.telemetry)
            .send_histograms_as_distributions(self.histograms_as_distributions);

        match self.histogram_sampling {
            Some(size) => {
                builder = builder
                    .with_histogram_sampling(true)
                    .with_histogram_reservoir_size(size);
            }
            None => builder = builder.with_histogram_sampling(false),
        }

        builder
            .install()
            .context("Failed to install DogStatsD exporter")?;

        Ok(())
    }
}

/// Defines the strategy used for aggregating data to send to the remote server.
#[derive(Debug, Default, Clone, serde::Deserialize)]
pub enum AggregationMode {
    /// Updates are sent more frequently, but reduces network traffic by not sending timestamps.
    /// Data is flushed every 3 seconds by default.
    #[default]
    Conservative,
    /// Updates are sent less frequently, but timestamps are sent with the aggregated data. Data is
    /// flushed every 10 seconds by default.
    Aggressive,
}

impl From<AggregationMode> for metrics_exporter_dogstatsd::AggregationMode {
    fn from(value: AggregationMode) -> Self {
        match value {
            AggregationMode::Conservative => Self::Conservative,
            AggregationMode::Aggressive => Self::Aggressive,
        }
    }
}
