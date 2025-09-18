use std::{
    ffi::CStr,
    fmt,
    net::SocketAddr,
    str::{FromStr, Utf8Error},
};

use aranya_daemon_api as api;
use aranya_policy_text::Text;
use tracing::error;

use crate::error::{self, Error};

/// A device's network identifier.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NetIdentifier(pub(super) Text);

impl NetIdentifier {
    pub fn into_api(self) -> api::NetIdentifier {
        api::NetIdentifier(self.0)
    }

    pub fn from_api(id: api::NetIdentifier) -> Self {
        Self(id.0)
    }
}

impl AsRef<str> for NetIdentifier {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl TryFrom<SocketAddr> for NetIdentifier {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(addr: SocketAddr) -> Result<Self, Self::Error> {
        Self::try_from(addr.to_string())
    }
}

impl TryFrom<&str> for NetIdentifier {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(id: &str) -> Result<Self, Self::Error> {
        Text::from_str(id)
            .map_err(|_| InvalidNetIdentifier(()))
            .map(Self)
    }
}

impl TryFrom<&CStr> for NetIdentifier {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(id: &CStr) -> Result<Self, Self::Error> {
        Text::try_from(id)
            .map_err(|_| InvalidNetIdentifier(()))
            .map(Self)
    }
}

impl TryFrom<String> for NetIdentifier {
    type Error = InvalidNetIdentifier;

    #[inline]
    fn try_from(id: String) -> Result<Self, Self::Error> {
        Text::try_from(id)
            .map_err(|_| InvalidNetIdentifier(()))
            .map(Self)
    }
}

impl fmt::Display for NetIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The [`NetIdentifier`] is invalid.
#[derive(Debug, thiserror::Error)]
#[error("invalid net identifier")]
pub struct InvalidNetIdentifier(pub(crate) ());

impl From<InvalidNetIdentifier> for Error {
    #[inline]
    fn from(err: InvalidNetIdentifier) -> Self {
        error::other(err).into()
    }
}

impl From<Utf8Error> for InvalidNetIdentifier {
    #[inline]
    fn from(_err: Utf8Error) -> Self {
        Self(())
    }
}
