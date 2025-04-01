use crate::error::ConfigError;

/// A builder for adding parameters when adding or creating teams.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TeamConfigBuilder {}

impl TeamConfigBuilder {
    /// Creates a new builder for [`TeamConfig`]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`TeamConfig`] using the provided parameters
    pub fn build(self) -> Result<TeamConfig, ConfigError> {
        Ok(TeamConfig {})
    }
}

/// Configuration info for adding and creating teams.
pub struct TeamConfig {}

impl From<TeamConfig> for aranya_daemon_api::TeamConfig {
    fn from(_value: TeamConfig) -> Self {
        Self {}
    }
}
