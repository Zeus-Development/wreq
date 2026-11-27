//! VIPER-PATCH(typed-proxy-errors): why a connection through a proxy failed,
//! as a public type, so that a caller tells the causes apart without reading
//! error messages.

use std::{error::Error as StdError, fmt};

// VIPER-PATCH(connect-challenge-fields): the type of a 407's fields.
use http::{HeaderMap, StatusCode};

use crate::error::BoxError;
// VIPER-PATCH(connect-407-retry): a connection kept after a 407.
use super::kept::ProxyConnection;

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
    // VIPER-PATCH(connect-challenge-fields): a 407's fields.
    fields: Option<Box<HeaderMap>>,
    // VIPER-PATCH(connect-407-retry): the connection a 407 left open.
    connection: Option<ProxyConnection>,
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
            fields: None,
            connection: None, // VIPER-PATCH(connect-407-retry)
        }
    }

    // VIPER-PATCH(connect-407-retry): keeps the connection a 407 left open.
    pub(crate) fn with_connection(mut self, connection: Option<ProxyConnection>) -> Self {
        self.connection = connection;
        self
    }

    /// The connection to the HTTP proxy that its 407 answer to `CONNECT`
    /// over HTTP/1.1 left open, its body read, for the retry with
    /// credentials to go on
    /// ([`RequestBuilder::proxy_connection`](crate::RequestBuilder::proxy_connection));
    /// `None` for any other failure, or when the 407 closed or may close
    /// the connection.
    // VIPER-PATCH(connect-407-retry): the kept connection.
    pub fn connection(&self) -> Option<ProxyConnection> {
        self.connection.clone()
    }

    // VIPER-PATCH(connect-challenge-fields): keeps a 407's fields.
    pub(crate) fn with_fields(mut self, fields: Option<Box<HeaderMap>>) -> Self {
        self.fields = fields;
        self
    }

    /// What failed.
    pub fn kind(&self) -> ProxyFailureKind {
        self.kind
    }

    /// The fields of the HTTP proxy's 407 answer to `CONNECT` (RFC 9110
    /// section 15.5.8), over HTTP/1.1 or as an HTTP/2 stream, its
    /// `Proxy-Authenticate` challenges among them (section 11.7.1), so that
    /// a caller can answer them; `None` for every other failure. A field
    /// that is not valid is left out.
    // VIPER-PATCH(connect-challenge-fields): the 407's fields.
    pub fn headers(&self) -> Option<&HeaderMap> {
        self.fields.as_deref()
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
