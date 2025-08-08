//! Utilities for loading environment variables for the example.

use std::str::FromStr;

use anyhow::{Context, Result};
use aranya_daemon_api::Role;
use aranya_util::Addr;

/// Aranya device info.
#[derive(Clone, Debug)]
pub struct Device {
    /// Device name.
    pub name: String,
    /// AQC address.
    pub aqc_addr: Addr,
    /// TCP address.
    pub tcp_addr: Addr,
    /// Device's role.
    pub role: Role,
}

/// Environment variables.
#[derive(Debug)]
pub struct EnvVars {
    /// Owner device
    pub owner: Device,
    /// Admin device
    pub admin: Device,
    /// Operator device
    pub operator: Device,
    /// Member A device
    pub membera: Device,
    /// Member B device
    pub memberb: Device,
    /// List of devices
    pub devices: Vec<Device>,
}

impl EnvVars {
    /// Load device info from environment variables.
    pub fn load() -> Result<Self> {
        let list = [
            ("owner", Role::Owner),
            ("admin", Role::Admin),
            ("operator", Role::Operator),
            ("membera", Role::Member),
            ("memberb", Role::Member),
        ];
        let mut devices = Vec::new();
        for device in list {
            let device = Device {
                name: device.0.to_string(),
                aqc_addr: env_var(&format!("ARANYA_AQC_ADDR_{}", device.0.to_uppercase()))?,
                tcp_addr: env_var(&format!("ARANYA_TCP_ADDR_{}", device.0.to_uppercase()))?,
                role: device.1,
            };
            devices.push(device);
        }
        let owner = devices[0].clone();
        let admin = devices[1].clone();
        let operator = devices[2].clone();
        let membera = devices[3].clone();
        let memberb = devices[4].clone();
        Ok(Self {
            owner,
            admin,
            operator,
            membera,
            memberb,
            devices,
        })
    }
}

/// Parses an environment variable, including the name in the error.
fn env_var<T>(name: &str) -> Result<T>
where
    T: FromStr<Err: core::error::Error + Send + Sync + 'static>,
{
    (|| -> Result<T> { Ok(std::env::var(name)?.parse()?) })()
        .with_context(|| format!("bad `{name}`"))
}
