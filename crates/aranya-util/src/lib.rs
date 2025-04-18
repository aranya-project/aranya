//! Utilities for the Aranya project.
//!
//! This is an internal crate that provides common utility functions
//! and types used across various Aranya components like the client, daemon,
//! UDS API, and others. It includes modules for:
//!
//! - `addr`: Handling network addresses (hostnames, IPs, ports), DNS lookups,
//!   and conversions.
//! - `util`: Filesystem operations and shared memory path handling.
//!
//! This crate makes no promises on backwards compatibility.

pub mod addr;
pub mod util;

pub use addr::*;
pub use util::*;
