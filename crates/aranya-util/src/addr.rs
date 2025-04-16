//! Network address handling and utilities.
//!
//! This module provides the [`Addr`] type for representing network addresses
//! (hostname/IP and port) and associated functionality.
//!
//!
//! The Addr type supports parsing addresses from strings in various formats
//! (e.g., "spideroak.com:80", "192.168.1.1:8080", "[::1]:443"), asynchronous DNS
//! resolution via [`Addr::lookup`], and conversion to and from standard library
//! types like [`std::net::SocketAddr`], [`std::net::Ipv4Addr`], and
//! [`std::net::Ipv6Addr`].

use std::{
    cmp::Ordering,
    error, fmt,
    hash::{Hash, Hasher},
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Deref,
    slice, str,
    str::FromStr,
};

use anyhow::Result;
use buggy::Bug;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use tokio::net::{self, ToSocketAddrs};
use tracing::{debug, instrument};

macro_rules! const_assert {
    ($($tt:tt)*) => {
        const _: () = assert!($($tt)*);
    }
}

/// Represents a network address composed of a host (domain name, IPv4, or IPv6)
/// and a port number.
///
/// `Addr` ensures that the host part is a syntactically valid domain name or IP address.
/// It provides methods for DNS lookup, conversion to socket addresses, and serde
/// serialization.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Addr {
    host: Host,
    port: u16,
}
const_assert!(size_of::<Addr>() == 256);

impl Addr {
    /// Creates a new `Addr` from a host representation and a port number.
    ///
    /// The `host` can be a domain name (e.g., "spideroak.com"), an IPv4 address string
    /// (e.g., "192.168.1.1"), or an IPv6 address string (e.g., "::1").
    ///
    /// Returns an error if the host is not a valid domain name or IP address string.
    ///
    /// # Errors
    ///
    /// Returns `AddrError::InvalidAddr` if the `host` string is not a valid
    /// domain name or IP address.
    pub fn new<T>(host: T, port: u16) -> Result<Self, AddrError>
    where
        T: AsRef<str>,
    {
        let host = host.as_ref();
        let host = Host::from_domain(host)
            .or_else(|| host.parse::<Ipv4Addr>().ok().map(Into::into))
            .or_else(|| host.parse::<Ipv6Addr>().ok().map(Into::into))
            .ok_or(AddrError::InvalidAddr(
                "not a valid domain name or IP address",
            ))?;
        Ok(Self { host, port })
    }

    /// Returns a reference to the host part (domain name or IP address) of the `Addr`.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the port number of the `Addr`.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Performs an asynchronous DNS lookup for this `Addr`.
    ///
    /// Resolves the host part of the address to one or more [`SocketAddr`] values.
    #[instrument(skip_all, fields(host = %self))]
    pub async fn lookup(&self) -> io::Result<impl Iterator<Item = SocketAddr> + '_> {
        debug!("performing DNS lookup");
        net::lookup_host(Into::<(&str, u16)>::into(self)).await
    }

    /// Converts the `Addr` into a type that implements [`ToSocketAddrs`].
    pub fn to_socket_addrs(&self) -> impl ToSocketAddrs + '_ {
        Into::<(&str, u16)>::into(self)
    }
}

impl<'a> From<&'a Addr> for (&'a str, u16) {
    fn from(addr: &'a Addr) -> Self {
        (&addr.host, addr.port)
    }
}

impl<T> From<T> for Addr
where
    T: Into<SocketAddr>,
{
    fn from(value: T) -> Self {
        let addr = value.into();
        Self {
            host: addr.ip().into(),
            port: addr.port(),
        }
    }
}

impl FromStr for Addr {
    type Err = AddrError;

    /// Parses a string into an `Addr`.
    ///
    /// The string can be in several forms:
    /// - `host:port` (e.g., "spideroak.com:80", "192.168.1.1:8080")
    /// - IPv6 address with port: `[ipv6_addr]:port` (e.g., "[::1]:443")
    /// - A string representation of a `SocketAddr` (which `std::net::SocketAddr::from_str` can parse).
    ///
    /// This function first attempts to parse using [`SocketAddr`], then falls
    /// back to splitting the string at the first ":" character to parse the
    /// host and port.
    ///
    /// # Errors
    ///
    /// Returns `AddrError::InvalidAddr` if the string format is invalid or the port
    /// number is malformed.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = SocketAddr::from_str(s) {
            return Ok(addr.into());
        }
        match s.split_once(':') {
            Some((host, port)) => {
                let port = port
                    .parse()
                    .map_err(|_| AddrError::InvalidAddr("invalid port syntax"))?;
                Self::new(host, port)
            }
            None => Err(AddrError::InvalidAddr("missing ':' in `host:port`")),
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host().contains(':') {
            let ip = Ipv6Addr::from_str(self.host()).map_err(|_| fmt::Error)?;
            SocketAddr::from((ip, self.port())).fmt(f)
        } else {
            write!(f, "{}:{}", self.host(), self.port())
        }
    }
}

impl Serialize for Addr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Addr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AddrVisitor;
        impl Visitor<'_> for AddrVisitor {
            type Value = Addr;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a 'host:port' network address")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(AddrVisitor)
    }
}

/// A hostname.
#[derive(Copy, Clone)]
struct Host {
    // NB: `Host` is exactly 254 bytes long. This allows `Addr`
    // to be exactly 256 bytes long.
    len: u8,
    buf: [u8; 253],
}

impl Host {
    /// Creates a `Host` from a domain name.
    fn from_domain(domain: &str) -> Option<Self> {
        if !is_domain_name(domain) {
            None
        } else {
            Self::try_from_str(domain)
        }
    }

    /// Creates a `Host` from an IPv4 address.
    fn from_ipv4(ip: &Ipv4Addr) -> Self {
        Self::from_fmt(FmtBuf::fmt_ipv4(ip))
    }

    /// Creates a `Host` from an IPv6 address.
    fn from_ipv6(ip: &Ipv6Addr) -> Self {
        Self::from_fmt(FmtBuf::fmt_ipv6(ip))
    }

    #[inline(always)]
    fn try_from_str(s: &str) -> Option<Self> {
        let mut buf = [0u8; 253];
        let src = s.as_bytes();
        buf.get_mut(..src.len())?.copy_from_slice(src);
        Some(Self {
            // We copied <= 253 bytes, so `src.len() < u8::MAX`.
            len: src.len() as u8,
            buf,
        })
    }

    #[inline(always)]
    fn from_fmt(fmt: FmtBuf) -> Self {
        debug_assert!(fmt.len < 253);

        // NB: the compiler can prove that `len` is in bounds.
        let mut buf = [0u8; 253];
        buf.copy_from_slice(&fmt.buf[..253]);
        Self { len: fmt.len, buf }
    }

    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: the buffer is always valid and length is
        // correct.
        unsafe { slice::from_raw_parts(self.buf.as_ptr(), usize::from(self.len)) }
    }

    #[inline(always)]
    fn as_str(&self) -> &str {
        // SAFETY: `Host` only stores valid UTF-8.
        unsafe { str::from_utf8_unchecked(self.as_bytes()) }
    }
}

impl Eq for Host {}
impl PartialEq for Host {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Ord for Host {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(self.as_str(), other.as_str())
    }
}

impl PartialOrd for Host {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl Hash for Host {
    #[inline]
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        Hash::hash(self.as_str(), state)
    }
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Deref for Host {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl<T> From<T> for Host
where
    T: Into<IpAddr>,
{
    #[inline]
    fn from(ip: T) -> Self {
        match ip.into() {
            IpAddr::V4(addr) => Self::from_ipv4(&addr),
            IpAddr::V6(addr) => Self::from_ipv6(&addr),
        }
    }
}

/// Reports whether `s` is a valid domain name.
///
/// See
/// <https://github.com/golang/go/blob/a66a3bf494f652bc4fb209d861cbdba1dea71303/src/net/dnsclient.go#L78>.
fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }
    if s.is_empty() || s.len() > 253 {
        return false;
    }

    let mut last = b'.';
    let mut non_numeric = false;
    let mut part_len = 0;
    for c in s.as_bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                part_len += 1;
            }
            b'0'..=b'9' => {
                part_len += 1;
            }
            b'-' => {
                if last == b'.' {
                    return false;
                }
                part_len += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' {
                    return false;
                }
                if part_len > 63 || part_len == 0 {
                    return false;
                }
                part_len = 0;
            }
            _ => return false,
        };
        last = *c;
    }
    if last == b'-' || part_len > 63 {
        return false;
    }
    non_numeric
}

/// Used to format IP addresses.
struct FmtBuf {
    /// The number of bytes written.
    len: u8,
    /// The size of this buffer lets the compiler prove that all
    /// writes are in bounds without panicking.
    ///
    /// Contents are `buf[..len]`.
    buf: [u8; 256],
}

impl FmtBuf {
    /// Creates a new `FmtBuf`.
    #[inline(always)]
    const fn new() -> Self {
        Self {
            len: 0,
            buf: [0u8; 256],
        }
    }

    /// The number of bytes that can still be written to the
    /// buffer.
    #[inline(always)]
    fn available(&self) -> usize {
        self.buf.len() - usize::from(self.len)
    }

    /// Returns the used portion of the buffer.
    #[inline(always)]
    #[cfg(test)]
    #[allow(clippy::indexing_slicing)]
    fn as_bytes(&self) -> &[u8] {
        // NB: the compiler can prove that `len` is in bounds.
        &self.buf[..usize::from(self.len)]
    }

    /// Writes `c` to the buffer.
    #[inline(always)]
    #[allow(clippy::indexing_slicing)]
    fn write(&mut self, c: u8) {
        debug_assert!(self.available() > 0);

        // NB: the compiler can prove that `self.idx` is in
        // bounds.
        self.buf[usize::from(self.len)] = c;
        self.len += 1;
    }

    /// Writes `s` to the buffer.
    #[inline(always)]
    fn write_str(&mut self, s: &str) {
        debug_assert!(self.available() >= s.len());

        for c in s.as_bytes() {
            self.write(*c);
        }
    }

    /// Writes `x` as a base-10 integer to the buffer.
    #[inline(always)]
    fn itoa10(&mut self, x: u8) {
        if x >= 100 {
            self.write(base10(x / 100))
        }
        if x >= 10 {
            self.write(base10(x / 10 % 10))
        }
        self.write(base10(x % 10))
    }

    /// Writes `x` as a base-16 integer to the buffer.
    #[inline(always)]
    fn itoa16(&mut self, x: u16) {
        if x >= 0x1000 {
            self.write(base16((x >> 12) as u8));
        }
        if x >= 0x100 {
            self.write(base16((x >> 8 & 0xf) as u8));
        }
        if x >= 0x10 {
            self.write(base16((x >> 4 & 0x0f) as u8));
        }
        self.write(base16((x & 0x0f) as u8));
    }

    /// Formats `ip` in its dotted quad notation.
    fn fmt_ipv4(ip: &Ipv4Addr) -> Self {
        let octets = ip.octets();

        let mut buf = Self::new();
        buf.itoa10(octets[0]);
        buf.write(b'.');
        buf.itoa10(octets[1]);
        buf.write(b'.');
        buf.itoa10(octets[2]);
        buf.write(b'.');
        buf.itoa10(octets[3]);
        buf
    }

    /// Formats `ip` per [RFC
    /// 5952](https://tools.ietf.org/html/rfc5952).
    fn fmt_ipv6(ip: &Ipv6Addr) -> Self {
        let mut buf = Self::new();

        if let Some(ip) = ip.to_ipv4_mapped() {
            let octets = ip.octets();
            buf.write_str("::ffff:");
            buf.itoa10(octets[0]);
            buf.write(b'.');
            buf.itoa10(octets[1]);
            buf.write(b'.');
            buf.itoa10(octets[2]);
            buf.write(b'.');
            buf.itoa10(octets[3]);
            return buf;
        }

        let segments = ip.segments();

        let zeros = {
            #[derive(Copy, Clone, Default)]
            struct Span {
                start: usize,
                len: usize,
            }
            impl Span {
                const fn contains(&self, idx: usize) -> bool {
                    self.start <= idx && idx < self.start + self.len
                }
            }

            let mut max = Span::default();
            let mut cur = Span::default();

            for (i, &seg) in segments.iter().enumerate() {
                if seg == 0 {
                    if cur.len == 0 {
                        cur.start = i;
                    }
                    cur.len += 1;

                    if cur.len >= 2 && cur.len > max.len {
                        max = cur;
                    }
                } else {
                    cur = Span::default();
                }
            }
            max
        };

        // TODO(eric): if we make this a little simpler we can
        // probably convince the compiler to elide all bounds
        // checks. That would let us make the internal buffer
        // 253 bytes.
        let mut iter = segments.iter().enumerate();
        while let Some((i, &seg)) = iter.next() {
            if zeros.contains(i) {
                buf.write_str("::");

                if let Some((_, &seg)) = iter.nth(zeros.len - 1) {
                    buf.itoa16(seg);
                }
            } else {
                if i > 0 {
                    buf.write(b':')
                }
                buf.itoa16(seg);
            }
        }
        buf
    }
}

/// Converts `c`, which must be in `0..=9`, to its base-10
/// representation.
const fn base10(x: u8) -> u8 {
    debug_assert!(x <= 9);

    x + b'0'
}

/// Converts `c`, which must be in `0..=15`, to its base-16
/// representation.
const fn base16(x: u8) -> u8 {
    debug_assert!(x <= 15);

    if x < 10 {
        base10(x)
    } else {
        x - 10 + b'a'
    }
}

/// An error returned by [`Addr`].
#[derive(Debug)]
pub enum AddrError {
    /// An internal bug was discovered.
    Bug(Bug),
    /// The provided address string is invalid.
    InvalidAddr(&'static str),
}

impl error::Error for AddrError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Bug(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bug(err) => write!(f, "{err}"),
            Self::InvalidAddr(msg) => {
                write!(f, "invalid network address: {msg}")
            }
        }
    }
}

impl From<Bug> for AddrError {
    fn from(err: Bug) -> Self {
        Self::Bug(err)
    }
}

#[allow(clippy::indexing_slicing, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base10() {
        const DIGITS: &[u8] = b"0123456789";
        for x in 0..=9u8 {
            let want = DIGITS[x as usize];
            let got = base10(x);
            assert_eq!(got, want);
        }
    }

    #[test]
    fn test_base16() {
        const DIGITS: &[u8] = b"0123456789abcdef";
        for x in 0..=15u8 {
            let want = DIGITS[x as usize];
            let got = base16(x);
            assert_eq!(got, want);
        }
    }

    #[test]
    fn test_addr_parse() {
        let tests = ["127.0.0.1:8080", "[2001:db8::1]:8080"];
        for test in tests {
            let got = Addr::from_str(test).unwrap();
            let want = SocketAddr::from_str(test).unwrap();
            assert_eq!(got, want.into());
        }
    }

    #[test]
    fn test_host_ipv4() {
        let ips = [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(4, 3, 2, 1),
            Ipv4Addr::new(127, 127, 127, 127),
            Ipv4Addr::new(100, 10, 1, 0),
        ];
        for (i, ip) in ips.into_iter().enumerate() {
            let want = ip.to_string();
            let got = String::from_utf8(FmtBuf::fmt_ipv4(&ip).as_bytes().to_vec())
                .expect("`FmtBuf` should be valid UTF-8");
            assert_eq!(got, want, "#{i}");
        }
    }

    #[test]
    fn test_host_ipv6() {
        let ips = [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xc000, 0x280),
            Ipv6Addr::new(
                0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
            ),
            Ipv6Addr::new(0xae, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(1, 0, 0, 4, 0, 0, 0, 8),
            Ipv6Addr::new(1, 0, 0, 4, 5, 0, 0, 8),
            Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
            Ipv6Addr::new(8, 7, 6, 5, 4, 3, 2, 1),
            Ipv6Addr::new(127, 127, 127, 127, 127, 127, 127, 127),
            Ipv6Addr::new(16, 16, 16, 16, 16, 16, 16, 16),
        ];
        for (i, ip) in ips.into_iter().enumerate() {
            let want = ip.to_string();
            let got = String::from_utf8(FmtBuf::fmt_ipv6(&ip).as_bytes().to_vec())
                .expect("`FmtBuf` should be valid UTF-8");
            assert_eq!(got, want, "#{i}");
        }
    }
}
