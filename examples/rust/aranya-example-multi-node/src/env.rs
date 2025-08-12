//! Utilities for loading environment variables for the example.

use std::{env, net::Ipv4Addr, path::Path, str::FromStr};

use anyhow::{Context, Result};
use aranya_daemon_api::Role;
use aranya_util::Addr;
use tokio::fs;

const DEVICE_LIST: [(&str, Role); 5] = [
    ("owner", Role::Owner),
    ("admin", Role::Admin),
    ("operator", Role::Operator),
    ("membera", Role::Member),
    ("memberb", Role::Member),
];

/// Aranya device info.
#[derive(Clone, Debug)]
pub struct Device {
    /// Device name.
    pub name: String,
    /// AQC address.
    pub aqc_addr: Addr,
    /// TCP address.
    pub tcp_addr: Addr,
    /// Sync address.
    pub sync_addr: Addr,
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
        let mut devices = Vec::new();
        for device in DEVICE_LIST {
            let device = Device {
                name: device.0.to_string(),
                aqc_addr: env_var(&format!("ARANYA_AQC_ADDR_{}", device.0.to_uppercase()))?,
                tcp_addr: env_var(&format!("ARANYA_TCP_ADDR_{}", device.0.to_uppercase()))?,
                sync_addr: env_var(&format!("ARANYA_SYNC_ADDR_{}", device.0.to_uppercase()))?,
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

    /// Generate environment file.
    pub async fn generate(&self, path: &Path) -> Result<()> {
        let mut buf = "".to_string();
        buf += "export ARANYA_EXAMPLE=info\r\n";
        for device in &self.devices {
            buf += &format!(
                "export ARANYA_SYNC_ADDR_{}={}\r\n",
                device.name.to_uppercase(),
                device.sync_addr
            );
            buf += &format!(
                "export ARANYA_AQC_ADDR_{}={}\r\n",
                device.name.to_uppercase(),
                device.aqc_addr
            );
            buf += &format!(
                "export ARANYA_TCP_ADDR_{}={}\r\n",
                device.name.to_uppercase(),
                device.tcp_addr
            );
        }
        fs::write(path, buf).await?;
        Ok(())
    }

    /// Set environment variables.
    pub fn set(&self) {
        env::set_var("ARANYA_EXAMPLE", "info");
        for device in &self.devices {
            env::set_var(
                format!("ARANYA_SYNC_ADDR_{}", device.name.to_uppercase()),
                device.sync_addr.to_string(),
            );
            env::set_var(
                format!("ARANYA_AQC_ADDR_{}", device.name.to_uppercase()),
                device.aqc_addr.to_string(),
            );
            env::set_var(
                format!("ARANYA_TCP_ADDR_{}", device.name.to_uppercase()),
                device.tcp_addr.to_string(),
            );
        }
    }
}

impl Default for EnvVars {
    fn default() -> Self {
        let mut devices = Vec::new();
        let mut port = 14001;
        for device in DEVICE_LIST {
            let sync_addr = Addr::from((Ipv4Addr::LOCALHOST, port));
            port += 1;
            let aqc_addr = Addr::from((Ipv4Addr::LOCALHOST, port));
            port += 1;
            let tcp_addr = Addr::from((Ipv4Addr::LOCALHOST, port));
            port += 1;
            let device = Device {
                name: device.0.to_string(),
                aqc_addr,
                tcp_addr,
                sync_addr,
                role: device.1,
            };
            devices.push(device);
        }
        let owner = devices[0].clone();
        let admin = devices[1].clone();
        let operator = devices[2].clone();
        let membera = devices[3].clone();
        let memberb = devices[4].clone();
        Self {
            owner,
            admin,
            operator,
            membera,
            memberb,
            devices,
        }
    }
}

/// Parses an environment variable, including the name in the error.
fn env_var<T>(name: &str) -> Result<T>
where
    T: FromStr<Err: core::error::Error + Send + Sync + 'static>,
{
    (|| -> Result<T> { Ok(env::var(name)?.parse()?) })().with_context(|| format!("bad `{name}`"))
}
