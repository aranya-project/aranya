use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::Deserialize;

mod prometheus;

/// Configuration for metrics collection and exporting
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    pub mode: MetricsMode,
    pub interval: Duration,
    pub job_name: String,
}

impl MetricsConfig {
    pub fn install(&self) -> Result<()> {
        match &self.mode {
            MetricsMode::Prometheus(prometheus) => {
                prometheus.install(self)?;
            }
            MetricsMode::Tracing => {}
        }

        Ok(())
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            mode: MetricsMode::default(),
            interval: Duration::from_millis(100),
            job_name: format!(
                "aranya_demo_{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("We're past the Unix Epoch")
                    .as_secs()
            ),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub enum MetricsMode {
    Prometheus(prometheus::PrometheusConfig),
    //DataDog(DataDogConfig),
    Tracing,
}

impl Default for MetricsMode {
    fn default() -> Self {
        Self::Prometheus(prometheus::PrometheusConfig::default())
    }
}
