use crate::error::ConfigError;

/// A configuration for creating or adding a team to a daemon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamConfig {
    version: u32,
}

impl TeamConfig {
    /// The minimum version of the config supported for reading
    pub const MINIMUM_VERSION: u32 = 1;

    /// The latest version of the `TeamConfig`
    pub const CURRENT_VERSION: u32 = 1;

    /// Creates a new `TeamConfig`
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the version of the `TeamConfig`
    pub fn with_version(mut self, version: u32) -> Result<Self, ConfigError> {
        if version < Self::MINIMUM_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                expected: Self::MINIMUM_VERSION,
                got: version,
            });
        }
        self.version = version;
        Ok(self)
    }

    /// Gets the version of the `TeamConfig`.
    pub const fn version(&self) -> u32 {
        self.version
    }
}

impl Default for TeamConfig {
    fn default() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
        }
    }
}
