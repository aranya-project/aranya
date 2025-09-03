//! Shared memory utility functions and types.

use std::str::FromStr;

use aranya_fast_channels::shm;

/// An owned, validated buffer representing a shared memory path string.
///
/// Shared memory paths often have specific syntax requirements (e.g., starting
/// with '/' and containing only a single slash). The requirements for
/// shared memory path also depend on the operating system.
/// `ShmPathBuf` wraps a `Vec<u8>` but ensures (upon creation via `FromStr`
/// or `TryFrom`) that the content represents a valid shared memory path
/// according to [`aranya_fast_channels::shm::Path::validate`].
///
/// # Errors
///
/// The `FromStr` and `TryFrom` implementations return `shm::InvalidPathError`
/// if the input string is not a valid shared memory path.
#[derive(Clone, Debug)]
pub struct ShmPathBuf(Vec<u8>);

impl AsRef<shm::Path> for ShmPathBuf {
    fn as_ref(&self) -> &shm::Path {
        // TODO(eric): I guess `Path` needs a `new_unchecked`
        // method or something.
        #[allow(clippy::expect_used)]
        shm::Path::from_bytes(&self.0[..]).expect("should already be validated")
    }
}

impl FromStr for ShmPathBuf {
    type Err = shm::InvalidPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut path = s.as_bytes().to_vec();
        path.push(0);
        shm::Path::validate(&path[..])?;
        Ok(ShmPathBuf(path))
    }
}

impl TryFrom<&str> for ShmPathBuf {
    type Error = shm::InvalidPathError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse::<Self>()
    }
}

impl TryFrom<String> for ShmPathBuf {
    type Error = shm::InvalidPathError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse::<Self>()
    }
}
