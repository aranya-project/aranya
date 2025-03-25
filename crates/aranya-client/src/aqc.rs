//! AFC support.
//!
//! # Wire Format
//!
//! ```text
//! magic || len || msg
//! ```
//!
//! - `magic` is a 32-bit little-endian integer with the magic
//!   value `"AFC\0"`.
//! - `len` is a 32-bit little endian integer that contains the
//!   size in bytes of `msg`.
//! - `msg`: A postcard-encoded `StreamMsg`.

use std::{path::Path, str::FromStr as _};

use anyhow::anyhow;
pub use aranya_daemon_api::AfcId;
use aranya_daemon_api::CS;
use aranya_fast_channels::shm::{Flag, Mode, ReadState};
pub use aranya_fast_channels::Label;
use aranya_util::ShmPathBuf;
use tracing::debug;

use crate::error::AfcError;

/// Setup the Aranya Client's read side of the AQC channel keys shared memory.
pub(crate) fn setup_aqc_shm(shm_path: &Path, max_chans: usize) -> Result<ReadState<CS>, AfcError> {
    debug!(?shm_path, "setting up aqc shm read side");

    let Some(path) = shm_path.to_str() else {
        return Err(anyhow!("unable to convert shm path to string").into());
    };
    let path = ShmPathBuf::from_str(path).map_err(AfcError::ShmPathParse)?;
    let read = ReadState::open(&path, Flag::OpenOnly, Mode::ReadWrite, max_chans)
        .map_err(Into::into)
        .map_err(AfcError::ShmReadState)?;
    Ok(read)
}
