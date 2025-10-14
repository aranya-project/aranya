//! Utilities for loading environment variables for the example.

use std::{env, path::Path, str::FromStr};

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result};
use aranya_client::client::Role;
use aranya_util::Addr;
use tokio::fs;

/// Environment variable name constants.
const LOG_LEVEL_ENV_VAR: &str = "ARANYA_EXAMPLE";
const ONBOARDING_PASSPHRASE_ENV_VAR: &str = "ARANYA_ONBOARDING_PASSPHRASE";
const AQC_ADDR_ENV_VAR: &str = "ARANYA_AQC_ADDR";
const TCP_ADDR_ENV_VAR: &str = "ARANYA_TCP_ADDR";
const SYNC_ADDR_ENV_VAR: &str = "ARANYA_SYNC_ADDR";

const DEVICE_LIST: [(&str, Role); 5] = [
    ("owner", Role::Owner),
    ("admin", Role::Admin),
    ("operator", Role::Operator),
    ("membera", Role::Member),
    ("memberb", Role::Member),
];

/// Environment variables.
#[derive(Debug, Clone)]
pub struct EnvVars {
    /// Tracing log level.
    pub level: String,
    /// Onboarding passphrase for encrypting team info with `age`.
    pub passphrase: SecretString,
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
}

impl EnvVars {
    /// Load device info from environment variables.
    pub fn load() -> Result<Self> {
        let level = env_var(LOG_LEVEL_ENV_VAR)?;
        let passphrase = SecretString::from(env_var::<String>(ONBOARDING_PASSPHRASE_ENV_VAR)?);
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
        let memberb = devices.pop().expect("expected device");
        let membera = devices.pop().expect("expected device");
        let operator = devices.pop().expect("expected device");
        let admin = devices.pop().expect("expected device");
        let owner = devices.pop().expect("expected device");
        Ok(Self {
            level,
            passphrase,
            owner,
            admin,
            operator,
            membera,
            memberb,
        })
    }

    /// Generate environment file.
    pub async fn generate(&self, path: &Path) -> Result<()> {
        let mut buf = "".to_string();
        buf += &format!("export {}={}\r\n", LOG_LEVEL_ENV_VAR, self.level);
        buf += &format!(
            "export {}={}\r\n",
            ONBOARDING_PASSPHRASE_ENV_VAR,
            self.passphrase.expose_secret()
        );
        for device in self.devices() {
            buf += &format!(
                "export {}_{}={}\r\n",
                SYNC_ADDR_ENV_VAR,
                device.name.to_uppercase(),
                device.sync_addr
            );
            buf += &format!(
                "export {}_{}={}\r\n",
                AQC_ADDR_ENV_VAR,
                device.name.to_uppercase(),
                device.aqc_addr
            );
            buf += &format!(
                "export {}_{}={}\r\n",
                TCP_ADDR_ENV_VAR,
                device.name.to_uppercase(),
                device.tcp_addr
            );
        }
        fs::write(path, buf).await?;
        Ok(())
    }

    /// Set environment variables.
    pub fn set(&self) {
        // TODO: set_var() is not safe to call in a multi-threaded program.
        env::set_var("ARANYA_EXAMPLE", self.level.clone());
        env::set_var(
            ONBOARDING_PASSPHRASE_ENV_VAR,
            self.passphrase.expose_secret(),
        );
        for device in self.devices() {
            env::set_var(
                format!("{}_{}", SYNC_ADDR_ENV_VAR, device.name.to_uppercase()),
                device.sync_addr.to_string(),
            );
            env::set_var(
                format!("{}_{}", AQC_ADDR_ENV_VAR, device.name.to_uppercase()),
                device.aqc_addr.to_string(),
            );
            env::set_var(
                format!("{}_{}", TCP_ADDR_ENV_VAR, device.name.to_uppercase()),
                device.tcp_addr.to_string(),
            );
        }
    }

    /// Return an Iterator to the list of devices.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        vec![
            &self.owner,
            &self.admin,
            &self.operator,
            &self.membera,
            &self.memberb,
        ]
        .into_iter()
    }
}

/// Default environment variables.
impl Default for EnvVars {
    fn default() -> Self {
        Self {
            level: "info".into(),
            passphrase: "passphrase".into(),
            owner: Device {
                name: "owner".into(),
                aqc_addr: Addr::from_str("127.0.0.1:10000").expect("expected addr"),
                tcp_addr: Addr::from_str("127.0.0.1:10001").expect("expected addr"),
                sync_addr: Addr::from_str("127.0.0.1:10002").expect("expected addr"),
                role: Role::Owner,
            },
            admin: Device {
                name: "admin".into(),
                aqc_addr: Addr::from_str("127.0.0.1:10003").expect("expected addr"),
                tcp_addr: Addr::from_str("127.0.0.1:10004").expect("expected addr"),
                sync_addr: Addr::from_str("127.0.0.1:10005").expect("expected addr"),
                role: Role::Admin,
            },
            operator: Device {
                name: "operator".into(),
                aqc_addr: Addr::from_str("127.0.0.1:10006").expect("expected addr"),
                tcp_addr: Addr::from_str("127.0.0.1:10007").expect("expected addr"),
                sync_addr: Addr::from_str("127.0.0.1:10008").expect("expected addr"),
                role: Role::Operator,
            },
            membera: Device {
                name: "membera".into(),
                aqc_addr: Addr::from_str("127.0.0.1:10009").expect("expected addr"),
                tcp_addr: Addr::from_str("127.0.0.1:10010").expect("expected addr"),
                sync_addr: Addr::from_str("127.0.0.1:10011").expect("expected addr"),
                role: Role::Member,
            },
            memberb: Device {
                name: "memberb".into(),
                aqc_addr: Addr::from_str("127.0.0.1:10012").expect("expected addr"),
                tcp_addr: Addr::from_str("127.0.0.1:10013").expect("expected addr"),
                sync_addr: Addr::from_str("127.0.0.1:10014").expect("expected addr"),
                role: Role::Member,
            },
        }
    }
}

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

/// Parses an environment variable, including the name in the error.
fn env_var<T>(name: &str) -> Result<T>
where
    T: FromStr<Err: core::error::Error + Send + Sync + 'static>,
{
    (|| -> Result<T> { Ok(env::var(name)?.parse()?) })().with_context(|| format!("bad `{name}`"))
}
