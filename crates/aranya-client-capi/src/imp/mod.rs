pub mod client;
pub mod config;
pub mod error;

pub use client::*;
pub use config::*;
pub use error::*;

/// A type to represent a span of time.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct Duration {
    pub nanos: u64,
}

impl From<Duration> for std::time::Duration {
    fn from(value: Duration) -> Self {
        std::time::Duration::from_nanos(value.nanos)
    }
}

pub const ARANYA_DURATION_MILLISECONDS: u64 = 1000 * ARANYA_DURATION_MICROSECONDS;
pub const ARANYA_DURATION_MICROSECONDS: u64 = 1000 * ARANYA_DURATION_NANOSECONDS;
pub const ARANYA_DURATION_NANOSECONDS: u64 = 1;
