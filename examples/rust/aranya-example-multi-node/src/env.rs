//! Utilities for loading environment variables for the example.

use std::{env, fmt::Write, net::Ipv4Addr, path::Path, str::FromStr};

use anyhow::{Context, Result};
use aranya_client::Addr;
use aranya_example_common::{ExposeSecret, SecretString};
use tokio::fs;

/// Environment variable name constants.
const LOG_LEVEL_ENV_VAR: &str = "ARANYA_EXAMPLE";
const ONBOARDING_PASSPHRASE_ENV_VAR: &str = "ARANYA_ONBOARDING_PASSPHRASE";
const AFC_ADDR_ENV_VAR: &str = "ARANYA_AFC_ADDR";
const TCP_ADDR_ENV_VAR: &str = "ARANYA_TCP_ADDR";
const SYNC_ADDR_ENV_VAR: &str = "ARANYA_SYNC_ADDR";

const DEVICE_LIST: [(&str, &str); 5] = [
    ("owner", "owner"),
    ("admin", "admin"),
    ("operator", "operator"),
    ("membera", "member"),
    ("memberb", "member"),
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
                afc_addr: env_var(&format!("ARANYA_AFC_ADDR_{}", device.0.to_uppercase()))?,
                tcp_addr: env_var(&format!("ARANYA_TCP_ADDR_{}", device.0.to_uppercase()))?,
                sync_addr: env_var(&format!("ARANYA_SYNC_ADDR_{}", device.0.to_uppercase()))?,
                role: device.1.to_string(),
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
        writeln!(buf, "export {}={}", LOG_LEVEL_ENV_VAR, self.level)?;
        writeln!(
            buf,
            "export {}={}",
            ONBOARDING_PASSPHRASE_ENV_VAR,
            self.passphrase.expose_secret()
        )?;
        for device in self.devices() {
            writeln!(
                buf,
                "export {}_{}={}",
                SYNC_ADDR_ENV_VAR,
                device.name.to_uppercase(),
                device.sync_addr
            )?;
            writeln!(
                buf,
                "export {}_{}={}",
                AFC_ADDR_ENV_VAR,
                device.name.to_uppercase(),
                device.afc_addr
            )?;
            writeln!(
                buf,
                "export {}_{}={}",
                TCP_ADDR_ENV_VAR,
                device.name.to_uppercase(),
                device.tcp_addr
            )?;
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
                format!("{}_{}", AFC_ADDR_ENV_VAR, device.name.to_uppercase()),
                device.afc_addr.to_string(),
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
                afc_addr: Addr::from((Ipv4Addr::LOCALHOST, 10000)),
                tcp_addr: Addr::from((Ipv4Addr::LOCALHOST, 10001)),
                sync_addr: Addr::from((Ipv4Addr::LOCALHOST, 10002)),
                role: "owner".to_string(),
            },
            admin: Device {
                name: "admin".into(),
                afc_addr: Addr::from((Ipv4Addr::LOCALHOST, 10003)),
                tcp_addr: Addr::from((Ipv4Addr::LOCALHOST, 10004)),
                sync_addr: Addr::from((Ipv4Addr::LOCALHOST, 10005)),
                role: "admin".to_string(),
            },
            operator: Device {
                name: "operator".into(),
                afc_addr: Addr::from((Ipv4Addr::LOCALHOST, 10006)),
                tcp_addr: Addr::from((Ipv4Addr::LOCALHOST, 10007)),
                sync_addr: Addr::from((Ipv4Addr::LOCALHOST, 10008)),
                role: "operator".to_string(),
            },
            membera: Device {
                name: "membera".into(),
                afc_addr: Addr::from((Ipv4Addr::LOCALHOST, 10009)),
                tcp_addr: Addr::from((Ipv4Addr::LOCALHOST, 10010)),
                sync_addr: Addr::from((Ipv4Addr::LOCALHOST, 10011)),
                role: "member".to_string(),
            },
            memberb: Device {
                name: "memberb".into(),
                afc_addr: Addr::from((Ipv4Addr::LOCALHOST, 10012)),
                tcp_addr: Addr::from((Ipv4Addr::LOCALHOST, 10013)),
                sync_addr: Addr::from((Ipv4Addr::LOCALHOST, 10014)),
                role: "member".to_string(),
            },
        }
    }
}

/// Aranya device info.
#[derive(Clone, Debug)]
pub struct Device {
    /// Device name.
    pub name: String,
    /// AFC address.
    pub afc_addr: Addr,
    /// TCP address.
    pub tcp_addr: Addr,
    /// Sync address.
    pub sync_addr: Addr,
    /// Device's role.
    pub role: String,
}

/// Parses an environment variable, including the name in the error.
fn env_var<T>(name: &str) -> Result<T>
where
    T: FromStr<Err: core::error::Error + Send + Sync + 'static>,
{
    (|| -> Result<T> { Ok(env::var(name)?.parse()?) })().with_context(|| format!("bad `{name}`"))
}
