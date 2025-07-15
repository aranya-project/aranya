use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::Deserialize;

mod prometheus;

// TODO(nikki): depending on how granular we want this, making it a repr(u8) and doing
// config.debug_log >= DebugLogType::PerProcess might be preferable.
#[derive(Debug, Default, Clone, Deserialize)]
pub enum DebugLogType {
    None,
    #[default]
    Total,
    PerProcess,
}

/// Configuration for metrics collection and exporting
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    pub mode: MetricsMode,
    pub interval: Duration,
    pub job_name: String,
    pub debug_logs: DebugLogType,
}

impl MetricsConfig {
    pub fn install(&self) -> Result<()> {
        match &self.mode {
            MetricsMode::Prometheus(prometheus) => {
                prometheus.install(self)?;
            }
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
            debug_logs: DebugLogType::Total,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub enum MetricsMode {
    Prometheus(prometheus::PrometheusConfig),
    //DataDog(DataDogConfig),
}

impl Default for MetricsMode {
    fn default() -> Self {
        Self::Prometheus(prometheus::PrometheusConfig::default())
    }
}
