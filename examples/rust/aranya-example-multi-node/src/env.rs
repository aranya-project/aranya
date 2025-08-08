use std::str::FromStr;

use anyhow::{Context, Result};
use aranya_util::Addr;
use tracing::info;

/// Environment variables.
#[derive(Debug)]
pub struct EnvVars {
    /// Owner AQC address.
    pub owner_aqc_addr: Addr,
    /// Owner TCP address.
    pub owner_tcp_addr: Addr,
    /// Admin AQC address.
    pub admin_aqc_addr: Addr,
    /// Admin TCP address.
    pub admin_tcp_addr: Addr,
    /// Operator AQC address.
    pub operator_aqc_addr: Addr,
    /// Operator TCP address.
    pub operator_tcp_addr: Addr,
    /// Member A AQC address.
    pub membera_aqc_addr: Addr,
    /// Member A TCP address.
    pub membera_tcp_addr: Addr,
    /// Member B AQC address.
    pub memberb_aqc_addr: Addr,
    /// Member B TCP address.
    pub memberb_tcp_addr: Addr,
}

impl EnvVars {
    /// Load environment variables.
    pub fn load() -> Result<Self> {
        let env = Self {
            owner_aqc_addr: env_var("ARANYA_AQC_ADDR_OWNER")?,
            owner_tcp_addr: env_var("ARANYA_TCP_ADDR_OWNER")?,
            admin_aqc_addr: env_var("ARANYA_AQC_ADDR_ADMIN")?,
            admin_tcp_addr: env_var("ARANYA_TCP_ADDR_ADMIN")?,
            operator_aqc_addr: env_var("ARANYA_AQC_ADDR_OPERATOR")?,
            operator_tcp_addr: env_var("ARANYA_TCP_ADDR_OPERATOR")?,
            membera_aqc_addr: env_var("ARANYA_AQC_ADDR_MEMBERA")?,
            membera_tcp_addr: env_var("ARANYA_TCP_ADDR_MEMBERA")?,
            memberb_aqc_addr: env_var("ARANYA_AQC_ADDR_MEMBERB")?,
            memberb_tcp_addr: env_var("ARANYA_TCP_ADDR_MEMBERB")?,
        };
        info!(?env);
        Ok(env)
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
