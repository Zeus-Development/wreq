use std::{
    marker::{PhantomData, Unpin},
    task::{self, Poll},
};

use bytes::BytesMut;
// VIPER-PATCH(typed-proxy-errors): StatusCode for the kept status.
use http::{HeaderMap, HeaderValue, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tower::{BoxError, Service};

// VIPER-PATCH(typed-proxy-errors): the public failure type.
use super::{
    Tunneling,
    failure::{ProxyFailure, ProxyFailureKind},
};
use crate::ext::UriExt;

/// Tunnel Proxy via HTTP CONNECT
///
/// This is a connector that can be used by the `Client`. It wraps
/// another connector, and after getting an underlying connection, it creates
/// an HTTP CONNECT tunnel over it.
#[derive(Debug)]
pub struct TunnelConnector<C> {
    headers: Headers,
    inner: C,
    proxy_dst: Uri,
}

#[derive(Clone, Debug)]
enum Headers {
    Empty,
    Auth(HeaderValue),
    Extra(HeaderMap),
}

#[derive(Debug)]
pub enum TunnelError {
    ConnectFailed(BoxError),
    Io(std::io::Error),
    Parse(httparse::Error),
    MissingHost,
    ProxyAuthRequired,
    TunnelUnexpectedEof,
    // VIPER-PATCH(typed-proxy-errors): the status is kept.
    TunnelUnsuccessful(Option<StatusCode>),
}

// VIPER-PATCH(typed-proxy-errors): each tunnel error's kind.
impl From<TunnelError> for ProxyFailure {
    fn from(error: TunnelError) -> Self {
        let kind = match error {
            TunnelError::ConnectFailed(_) => ProxyFailureKind::Connect,
            TunnelError::Io(_) => ProxyFailureKind::Handshake,
            TunnelError::Parse(_) => ProxyFailureKind::Malformed,
            TunnelError::ProxyAuthRequired => {
                ProxyFailureKind::Status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            }
            TunnelError::TunnelUnexpectedEof => ProxyFailureKind::Closed,
            TunnelError::TunnelUnsuccessful(Some(status)) => ProxyFailureKind::Status(status),
            TunnelError::MissingHost | TunnelError::TunnelUnsuccessful(None) => {
                ProxyFailureKind::Other
            }
        };
        ProxyFailure::new(kind, error)
    }
}

impl<C> TunnelConnector<C> {
    /// Create a new tunnel connector.
    ///
    /// This wraps an underlying connector, and stores the address of a
    /// tunneling proxy server.
    ///
    /// A `TunnelConnector` can then be called with any destination. The `proxy_dst` passed to
    /// `call` will not be used to create the underlying connection, but will
    /// be used in an HTTP CONNECT request sent to the proxy destination.
    pub fn new(proxy_dst: Uri, connector: C) -> Self {
        Self {
            headers: Headers::Empty,
            inner: connector,
            proxy_dst,
        }
    }

    /// Add `proxy-authorization` header value to the CONNECT request.
    pub fn with_auth(mut self, mut auth: HeaderValue) -> Self {
        // just in case the user forgot
        auth.set_sensitive(true);
        match self.headers {
            Headers::Empty => {
                self.headers = Headers::Auth(auth);
            }
            Headers::Auth(ref mut existing) => {
                *existing = auth;
            }
            Headers::Extra(ref mut extra) => {
                extra.insert(http::header::PROXY_AUTHORIZATION, auth);
            }
        }

        self
    }

    /// Add extra headers to be sent with the CONNECT request.
    ///
    /// If existing headers have been set, these will be merged.
    pub fn with_headers(mut self, mut headers: HeaderMap) -> Self {
        match self.headers {
            Headers::Empty => {
                self.headers = Headers::Extra(headers);
            }
            Headers::Auth(auth) => {
                headers
                    .entry(http::header::PROXY_AUTHORIZATION)
                    .or_insert(auth);
                self.headers = Headers::Extra(headers);
            }
            Headers::Extra(ref mut extra) => {
                extra.extend(headers);
            }
        }

        self
    }

    // VIPER-PATCH(h2-proxy-connect): an HTTP/1.1 `CONNECT` on a connection
    // to the proxy already made (one that did not select `h2`).
    pub(crate) async fn tunnel_over<T>(&self, conn: T, dst: &Uri) -> Result<T, TunnelError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let host = dst.host().ok_or(TunnelError::MissingHost)?;
        tunnel(conn, host, dst.port_or_default(), &self.headers).await
    }
}

impl<C> Service<Uri> for TunnelConnector<C>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = C::Response;
    type Error = TunnelError;
    type Future = Tunneling<C::Future, C::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(Into::into)
            .map_err(TunnelError::ConnectFailed)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let connecting = self.inner.call(self.proxy_dst.clone());
        let headers = self.headers.clone();

        Tunneling {
            fut: Box::pin(async move {
                let conn = connecting
                    .await
                    .map_err(Into::into)
                    .map_err(TunnelError::ConnectFailed)?;
                tunnel(
                    conn,
                    dst.host().ok_or(TunnelError::MissingHost)?,
                    dst.port_or_default(),
                    &headers,
                )
                .await
            }),
            _marker: PhantomData,
        }
    }
}

async fn tunnel<T>(mut conn: T, host: &str, port: u16, headers: &Headers) -> Result<T, TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = format!(
        "\
         CONNECT {host}:{port} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         "
    )
    .into_bytes();

    match headers {
        Headers::Auth(auth) => {
            buf.extend_from_slice(b"Proxy-Authorization: ");
            buf.extend_from_slice(auth.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        Headers::Extra(extra) => {
            for (name, value) in extra {
                buf.extend_from_slice(name.as_str().as_bytes());
                buf.extend_from_slice(b": ");
                buf.extend_from_slice(value.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
        }
        Headers::Empty => (),
    }

    // headers end
    buf.extend_from_slice(b"\r\n");

    conn.write_all(&buf).await.map_err(TunnelError::Io)?;
    conn.flush().await.map_err(TunnelError::Io)?;

    let mut buf = BytesMut::with_capacity(8192);

    loop {
        if conn.read_buf(&mut buf).await.map_err(TunnelError::Io)? == 0 {
            return Err(TunnelError::TunnelUnexpectedEof);
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut res = httparse::Response::new(&mut headers);
        match res.parse(&buf).map_err(TunnelError::Parse)? {
            httparse::Status::Partial => continue,
            httparse::Status::Complete(_) => match res.code {
                Some(200) => return Ok(conn),
                Some(407) => return Err(TunnelError::ProxyAuthRequired),
                // VIPER-PATCH(typed-proxy-errors): the status is kept.
                code => {
                    let status = code.and_then(|code| StatusCode::from_u16(code).ok());
                    return Err(TunnelError::TunnelUnsuccessful(status));
                }
            },
        }
    }
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tunnel error: ")?;

        f.write_str(match self {
            TunnelError::MissingHost => "missing destination host",
            TunnelError::ProxyAuthRequired => "proxy authorization required",
            TunnelError::Parse(_) => "invalid proxy response",
            TunnelError::TunnelUnexpectedEof => "unexpected end of file",
            // VIPER-PATCH(typed-proxy-errors): the message is unchanged.
            TunnelError::TunnelUnsuccessful(_) => "unsuccessful",
            TunnelError::ConnectFailed(_) => "failed to create underlying connection",
            TunnelError::Io(_) => "io error establishing tunnel",
        })
    }
}

impl std::error::Error for TunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TunnelError::Io(e) => Some(e),
            TunnelError::Parse(e) => Some(e),
            TunnelError::ConnectFailed(e) => Some(&**e),
            _ => None,
        }
    }
}
