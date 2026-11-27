use std::{
    marker::{PhantomData, Unpin},
    task::{self, Poll},
};

use bytes::BytesMut;
// VIPER-PATCH(typed-proxy-errors): StatusCode for the kept status.
// VIPER-PATCH(connect-head-fields): `Host` and the credentials as fields.
use http::{
    HeaderMap, HeaderValue, StatusCode, Uri,
    header::{HOST, PROXY_AUTHORIZATION},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tower::{BoxError, Service};
// VIPER-PATCH(connect-head-fields): the head's order and case.
use wreq_proto::ext::OnPreserveHeaderCallback;

use crate::header::OrigHeaderMap;

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
    // VIPER-PATCH(connect-head-fields): the head's order and case.
    order: Option<OrigHeaderMap>,
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
    // VIPER-PATCH(connect-challenge-fields): the 407's fields are kept.
    ProxyAuthRequired(Box<HeaderMap>),
    TunnelUnexpectedEof,
    // VIPER-PATCH(typed-proxy-errors): the status is kept.
    TunnelUnsuccessful(Option<StatusCode>),
}

// VIPER-PATCH(typed-proxy-errors): each tunnel error's kind.
impl From<TunnelError> for ProxyFailure {
    fn from(mut error: TunnelError) -> Self {
        // VIPER-PATCH(connect-challenge-fields): the 407's fields move to
        // the failure.
        let fields = match &mut error {
            TunnelError::ProxyAuthRequired(fields) => Some(std::mem::take(fields)),
            _ => None,
        };
        let kind = match error {
            TunnelError::ConnectFailed(_) => ProxyFailureKind::Connect,
            TunnelError::Io(_) => ProxyFailureKind::Handshake,
            TunnelError::Parse(_) => ProxyFailureKind::Malformed,
            TunnelError::ProxyAuthRequired(_) => {
                ProxyFailureKind::Status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            }
            TunnelError::TunnelUnexpectedEof => ProxyFailureKind::Closed,
            TunnelError::TunnelUnsuccessful(Some(status)) => ProxyFailureKind::Status(status),
            TunnelError::MissingHost | TunnelError::TunnelUnsuccessful(None) => {
                ProxyFailureKind::Other
            }
        };
        ProxyFailure::new(kind, error).with_fields(fields)
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
            order: None, // VIPER-PATCH(connect-head-fields)
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

    // VIPER-PATCH(connect-head-fields): the head's fields, `Host` among
    // them, written in `order`'s order and case.
    pub(crate) fn with_order(mut self, order: Option<OrigHeaderMap>) -> Self {
        self.order = order;
        self
    }

    // VIPER-PATCH(h2-proxy-connect): an HTTP/1.1 `CONNECT` on a connection
    // to the proxy already made (one that did not select `h2`).
    // VIPER-PATCH(connect-407-retry): a 407 that leaves the connection open
    // puts it in `kept`, for the caller's retry.
    pub(crate) async fn tunnel_over<T>(
        &self,
        conn: T,
        dst: &Uri,
        kept: &mut Option<T>,
    ) -> Result<T, TunnelError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let host = dst.host().ok_or(TunnelError::MissingHost)?;
        // VIPER-PATCH(connect-head-fields): with the order.
        let head = (&self.headers, self.order.as_ref());
        // VIPER-PATCH(connect-407-retry): where a 407 keeps the connection.
        tunnel(conn, host, dst.port_or_default(), head, Some(kept)).await
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
        let order = self.order.clone(); // VIPER-PATCH(connect-head-fields)

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
                    (&headers, order.as_ref()), // VIPER-PATCH(connect-head-fields)
                    None,                       // VIPER-PATCH(connect-407-retry)
                )
                .await
            }),
            _marker: PhantomData,
        }
    }
}

// VIPER-PATCH(connect-head-fields): the head's order with its fields.
// VIPER-PATCH(connect-407-retry): and where a 407 keeps the connection.
async fn tunnel<T>(
    conn: T,
    host: &str,
    port: u16,
    (headers, order): (&Headers, Option<&OrigHeaderMap>),
    kept: Option<&mut Option<T>>, // VIPER-PATCH(connect-407-retry)
) -> Result<T, TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = format!("CONNECT {host}:{port} HTTP/1.1\r\n").into_bytes();
    // VIPER-PATCH(connect-head-fields): `Host` and the fields in the
    // order's order and case, `Host` first when the order does not name it.
    if let Some(order) = order {
        ordered(&mut buf, (host, port), headers, order)?;
        return handshake(conn, buf, kept).await; // VIPER-PATCH(connect-407-retry)
    }
    buf.extend_from_slice(format!("Host: {host}:{port}\r\n").as_bytes());

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
    // VIPER-PATCH(connect-head-fields): the head written, its answer read.
    handshake(conn, buf, kept).await // VIPER-PATCH(connect-407-retry)
}

// VIPER-PATCH(connect-head-fields): the head's fields, `Host` among them,
// in `order`'s order and case, then the end of the head.
fn ordered(
    buf: &mut Vec<u8>,
    (host, port): (&str, u16),
    headers: &Headers,
    order: &OrigHeaderMap,
) -> Result<(), TunnelError> {
    let mut fields = match headers {
        Headers::Extra(extra) => extra.clone(),
        Headers::Auth(auth) => HeaderMap::from_iter([(PROXY_AUTHORIZATION, auth.clone())]),
        Headers::Empty => HeaderMap::new(),
    };
    let value =
        HeaderValue::from_str(&format!("{host}:{port}")).map_err(|_| TunnelError::MissingHost)?;
    fields.insert(HOST, value);
    let named = order.iter().any(|(name, _)| *name == HOST);
    if !named && let Some(value) = fields.remove(HOST) {
        buf.extend_from_slice(b"Host: ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    order.call_visit(&mut fields, &mut |name, value| {
        buf.extend_from_slice(name.as_ref());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    });
    buf.extend_from_slice(b"\r\n");
    Ok(())
}

// VIPER-PATCH(connect-head-fields): the head's write and its answer, as
// before, apart from the head's fields.
// VIPER-PATCH(connect-407-retry): a 407 whose connection stays open, its
// body read, puts it in `kept`.
async fn handshake<T>(
    mut conn: T,
    buf: Vec<u8>,
    kept: Option<&mut Option<T>>,
) -> Result<T, TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
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
            // VIPER-PATCH(connect-407-retry): the head's length.
            httparse::Status::Complete(end) => match res.code {
                Some(200) => return Ok(conn),
                // VIPER-PATCH(connect-challenge-fields): with its fields,
                // its `Proxy-Authenticate` challenges among them (RFC 9110
                // section 11.7.1).
                Some(407) => {
                    let fields = fields(res.headers);
                    // VIPER-PATCH(connect-407-retry): kept open when its
                    // head lets it be and its body is read.
                    let body = reusable(&res).map(|length| (length, buf.len() - end));
                    if let (Some(kept), Some((length, read))) = (kept, body)
                        && drain(&mut conn, length, read).await
                    {
                        *kept = Some(conn);
                    }
                    return Err(TunnelError::ProxyAuthRequired(fields));
                }
                // VIPER-PATCH(typed-proxy-errors): the status is kept.
                code => {
                    let status = code.and_then(|code| StatusCode::from_u16(code).ok());
                    return Err(TunnelError::TunnelUnsuccessful(status));
                }
            },
        }
    }
}

// VIPER-PATCH(connect-407-retry): the largest 407 body read to keep its
// connection; a larger one closes it.
const DRAINED: usize = 64 * 1024;

// VIPER-PATCH(connect-407-retry): the body length of a 407 whose connection
// stays open after it: HTTP/1.1 without `Connection: close` (RFC 9112
// section 9.3), its body framed by one `Content-Length` of at most `DRAINED`
// bytes and no `Transfer-Encoding` (section 6.3); `None` otherwise.
fn reusable(res: &httparse::Response<'_, '_>) -> Option<usize> {
    let named = |name: &'static str| {
        let headers = res.headers.iter();
        headers.filter(move |header| header.name.eq_ignore_ascii_case(name))
    };
    let close = |header: &httparse::Header<'_>| {
        let mut tokens = header.value.split(|byte| *byte == b',');
        tokens.any(|token| token.trim_ascii().eq_ignore_ascii_case(b"close"))
    };
    if res.version != Some(1) || named("connection").any(close) {
        return None;
    }
    if named("transfer-encoding").next().is_some() {
        return None;
    }
    let mut lengths = named("content-length");
    let length = std::str::from_utf8(lengths.next()?.value).ok()?;
    let length: usize = length.trim().parse().ok()?;
    (lengths.next().is_none() && length <= DRAINED).then_some(length)
}

// VIPER-PATCH(connect-407-retry): reads the rest of a 407's `length`-byte
// body, `read` bytes of which came with its head; false when the proxy
// closed first or sent more than the body.
async fn drain<T: AsyncRead + Unpin>(conn: &mut T, length: usize, read: usize) -> bool {
    let Some(rest) = length.checked_sub(read) else {
        return false;
    };
    let mut rest = vec![0; rest];
    conn.read_exact(&mut rest).await.is_ok()
}

// VIPER-PATCH(connect-challenge-fields): a head's parsed fields; one that is
// not a valid field is left out.
fn fields(parsed: &[httparse::Header<'_>]) -> Box<HeaderMap> {
    let field = |header: &httparse::Header<'_>| {
        let name = http::HeaderName::from_bytes(header.name.as_bytes()).ok()?;
        Some((name, HeaderValue::from_bytes(header.value).ok()?))
    };
    let mut fields = HeaderMap::new();
    for (name, value) in parsed.iter().filter_map(field) {
        fields.append(name, value);
    }
    Box::new(fields)
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tunnel error: ")?;

        f.write_str(match self {
            TunnelError::MissingHost => "missing destination host",
            TunnelError::ProxyAuthRequired(_) => "proxy authorization required",
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
