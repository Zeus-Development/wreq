//! VIPER-PATCH(typed-proxy-errors): why a connection through a proxy failed,
//! as a public type, so that a caller tells the causes apart without reading
//! error messages.

use std::{error::Error as StdError, fmt};

use http::StatusCode;

use crate::error::BoxError;

/// A failed connection through a proxy.
///
/// It is in the source chain of an [`Error`](crate::Error) whose
/// [`is_proxy_connect`](crate::Error::is_proxy_connect) is true: find it with
/// `downcast_ref` while walking [`source`](StdError::source). Its message is
/// fixed, and its source is the connector's error, whose own source is the
/// cause where there is one (an [`std::io::Error`] for
/// [`ProxyFailureKind::Connect`] and [`ProxyFailureKind::Handshake`]).
#[derive(Debug)]
pub struct ProxyFailure {
    kind: ProxyFailureKind,
    source: BoxError,
}

/// What failed in a connection through a proxy.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyFailureKind {
    /// The connection to the proxy itself failed.
    Connect,
    /// The HTTP proxy answered `CONNECT` with this status. wreq takes only a
    /// 200 as an established tunnel, although RFC 9110 section 9.3.6 makes
    /// any 2xx one, so another 2xx shows here too; a 407 asks for
    /// credentials.
    Status(StatusCode),
    /// The SOCKS5 proxy's reply field, 1 to 8 (RFC 1928 section 6).
    Socks5Reply(u8),
    /// The SOCKS5 proxy accepted none of the offered authentication methods
    /// (RFC 1928 section 3, `X'FF'`).
    Socks5NoAcceptableMethods,
    /// The SOCKS5 proxy refused the username and password with this status
    /// (RFC 1929 section 2).
    Socks5AuthRejected(u8),
    /// The proxy's reply is not valid HTTP or SOCKS.
    Malformed,
    /// The proxy ended the connection (an end of file) before its reply was
    /// complete, for `CONNECT` and SOCKS5 alike.
    Closed,
    /// Another I/O error during the handshake with the proxy, after the
    /// connection to it was made (such as a reset); the `io::Error` is below
    /// it in the chain.
    Handshake,
    /// Any other failure, such as a destination without a host.
    Other,
}

impl ProxyFailure {
    pub(crate) fn new(kind: ProxyFailureKind, source: impl Into<BoxError>) -> Self {
        Self {
            kind,
            source: source.into(),
        }
    }

    /// What failed.
    pub fn kind(&self) -> ProxyFailureKind {
        self.kind
    }
}

impl fmt::Display for ProxyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connection through the proxy failed")
    }
}

impl StdError for ProxyFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.source)
    }
}
