//! Utilities for the Aranya project.
//!
//! This crate provides common utility functions and types used across
//! various Aranya components. It includes modules for:
//!
//! - `addr`: Handling network addresses (hostnames, IPs, ports), DNS lookups,
//!   and conversions.
//! - `util`: Filesystem operations and shared memory path handling.

pub mod addr;
pub mod util;

pub use addr::*;
pub use util::*;
