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

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod addr;
pub mod error;
pub mod ready;
pub mod rustls;
pub mod s2n_quic;
// TODO: shm only needed by AFC.
pub mod shm;
pub mod task;
pub mod util;

pub use addr::*;
pub use shm::*;
pub use util::*;
