//! TCP networking.

mod client;
mod server;

#[cfg(test)]
mod tests;

pub use client::*;
pub use server::*;
