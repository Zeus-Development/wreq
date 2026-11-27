//! VIPER-PATCH(h2-proxy-connect): tunnels through an HTTPS proxy that
//! selected `h2` through ALPN, as `CONNECT` streams of one HTTP/2 connection
//! (RFC 9113 section 8.5), shared by the tunnels to that proxy while it stays
//! open. A proxy that selects another protocol, or none, gets an HTTP/1.1
//! `CONNECT` on the connection just made.

use std::{
    fmt, io,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode, Uri, header::PROXY_AUTHORIZATION};
use http_body_util::Empty;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower::{BoxError, Service};
use wreq_proto::{
    conn::http2::{Builder, SendRequest},
    // VIPER-PATCH(h2-proxy-profile): the client's options.
    http2::Http2Options,
    // VIPER-PATCH(connect-head-fields): sorts the `CONNECT` stream's fields.
    ext::OnPreserveHeaderCallback,
    rt::Executor as _,
    upgrade::{self, Upgraded},
};

use super::tunnel::TunnelError;
use crate::{
    // VIPER-PATCH(h2-proxy-addresses): the socket's addresses.
    conn::{Connected, Connection, TlsConn, http::HttpInfo, tls_info::TlsInfoFactory},
    ext::UriExt,
    // VIPER-PATCH(connect-head-fields): the `CONNECT` head's order.
    header::OrigHeaderMap,
    proxy::matcher::Intercept,
    rt::Executor,
    tls::{
        AlpnProtocol,
        conn::{HttpsConnector, MaybeHttpsStream},
    },
};

/// The open HTTP/2 connections to proxies, one per proxy (its URI,
/// credentials, headers and ALPN list); a closed one is dropped when the
/// next tunnel looks for its proxy.
// VIPER-PATCH(h2-proxy-profile): with the options they open with.
// VIPER-PATCH(h2-proxy-addresses): each with its socket's addresses.
#[derive(Clone, Default)]
pub(crate) struct Shared {
    open: Arc<Mutex<Vec<Open>>>,
    /// The HTTP/2 options each connection to a proxy opens with: the
    /// client's own, as its connections to origins do; `None` for
    /// wreq-proto's defaults.
    pub(crate) options: Option<Http2Options>,
}

// VIPER-PATCH(h2-proxy-addresses): an open connection: its proxy, its
// sender and its socket's addresses.
type Open = (Intercept, SendRequest<Empty<Bytes>>, Option<HttpInfo>);

/// A tunnel's first leg: a `CONNECT` stream, or a connection to the proxy
/// that did not select `h2`, for an HTTP/1.1 `CONNECT`.
pub(crate) enum Opened<T> {
    Stream(H2Tunnel),
    Http1(T),
}

/// VIPER-PATCH(request-connect-fields): `fields` are the request's own
/// `CONNECT` fields, in place of the proxy's of their names.
///
/// The tunnel through `proxy` to `dst`'s authority: a stream of the proxy's
/// shared HTTP/2 connection, opened with the proxy's ALPN list if none is
/// open. An error is a [`TunnelError`], as for an HTTP/1.1 tunnel: the
/// connection to the proxy failed, the proxy answered with a status other
/// than 200, or the stream or connection failed (`Io`), for example when the
/// proxy reset the stream.
pub(crate) async fn open<S, T>(
    shared: &Shared,
    proxy: &Intercept,
    // VIPER-PATCH(connect-head-fields): the head's order too.
    (alpn, fields, order): (&[AlpnProtocol], Option<&HeaderMap>, Option<&OrigHeaderMap>),
    mut connector: HttpsConnector<S>,
    dst: &Uri,
) -> Result<Opened<MaybeHttpsStream<T>>, TunnelError>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + fmt::Debug + Sync + Send + 'static,
{
    let host = dst.host().ok_or(TunnelError::MissingHost)?;
    let authority = format!("{host}:{}", dst.port_or_default());
    // VIPER-PATCH(h2-proxy-addresses): with the socket's addresses.
    let (mut sender, info) = match find(shared, proxy) {
        Some(found) => found,
        None => {
            connector.proxy_alpn(alpn);
            let io = connector
                .call(proxy.uri().clone())
                .await
                .map_err(TunnelError::ConnectFailed)?;
            let MaybeHttpsStream::Https(stream) = io else {
                return Ok(Opened::Http1(io));
            };
            if stream.ssl().selected_alpn_protocol() != Some(b"h2".as_slice()) {
                return Ok(Opened::Http1(MaybeHttpsStream::Https(stream)));
            }
            // VIPER-PATCH(h2-proxy-addresses): the TCP socket's, below TLS.
            let info = http_info(stream.get_ref());
            // VIPER-PATCH(h2-proxy-profile): with the client's options.
            let sender = handshake(TlsConn { stream }, shared.options.clone()).await?;
            let mut list = shared.open.lock().unwrap_or_else(PoisonError::into_inner);
            list.push((proxy.clone(), sender.clone(), info.clone()));
            (sender, info)
        }
    };
    let mut request = Request::builder().method(Method::CONNECT).uri(authority);
    if let Some(auth) = proxy.basic_auth() {
        request = request.header(PROXY_AUTHORIZATION, auth.clone());
    }
    let mut request = request.body(Empty::new()).map_err(failed)?;
    if let Some(headers) = proxy.custom_headers() {
        request.headers_mut().extend(headers.clone());
    }
    // VIPER-PATCH(request-connect-fields): the request's own fields.
    if let Some(fields) = fields {
        request.headers_mut().extend(fields.clone());
    }
    // VIPER-PATCH(connect-head-fields): in the request's order.
    if let Some(order) = order {
        order.call(request.headers_mut());
    }
    let response = sender
        .try_send_request(request)
        .await
        .map_err(|error| failed(error.into_error()))?;
    match response.status() {
        StatusCode::OK => {}
        // VIPER-PATCH(connect-challenge-fields): with the 407's fields.
        StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
            let fields = Box::new(response.headers().clone());
            return Err(TunnelError::ProxyAuthRequired(fields));
        }
        status => return Err(TunnelError::TunnelUnsuccessful(Some(status))),
    }
    let upgraded = upgrade::on(response).await.map_err(failed)?;
    // VIPER-PATCH(h2-proxy-addresses): with the socket's addresses.
    Ok(Opened::Stream(H2Tunnel(Mutex::new(upgraded), info)))
}

/// A failure of the HTTP/2 connection or stream, after the connection to
/// the proxy was made, as an I/O error of the tunnel's handshake.
fn failed(error: impl Into<BoxError>) -> TunnelError {
    TunnelError::Io(io::Error::other(error))
}

/// A clone of `proxy`'s open connection, after dropping closed ones.
// VIPER-PATCH(h2-proxy-addresses): with its socket's addresses.
fn find(
    shared: &Shared,
    proxy: &Intercept,
) -> Option<(SendRequest<Empty<Bytes>>, Option<HttpInfo>)> {
    let mut list = shared.open.lock().unwrap_or_else(PoisonError::into_inner);
    list.retain(|(_, sender, _)| !sender.is_closed());
    let found = list.iter().find(|(key, _, _)| key == proxy);
    found.map(|(_, sender, info)| (sender.clone(), info.clone()))
}

// VIPER-PATCH(h2-proxy-addresses): the local and peer addresses `io`'s
// connection gives, if any.
fn http_info(io: &impl Connection) -> Option<HttpInfo> {
    let mut extensions = http::Extensions::new();
    io.connected().set_extras(&mut extensions);
    extensions.remove::<HttpInfo>()
}

/// The HTTP/2 handshake with the proxy, its connection driven on the
/// runtime's executor.
// VIPER-PATCH(h2-proxy-profile): with `options` (SETTINGS and their order,
// the connection window, the HEADERS priority and pseudo-header order), or
// wreq-proto's defaults without them.
async fn handshake<T>(
    io: T,
    options: Option<Http2Options>,
) -> Result<SendRequest<Empty<Bytes>>, TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let exec = Executor::default();
    // VIPER-PATCH(h2-proxy-profile): the client's options, if any.
    let mut builder = Builder::new(exec.clone());
    if let Some(options) = options {
        builder = builder.options(options);
    }
    let (mut sender, conn) = builder
        .handshake(io)
        .await
        .map_err(failed)?;
    exec.execute(async move {
        drop(conn.await);
    });
    sender.ready().await.map_err(failed)?;
    Ok(sender)
}

/// One `CONNECT` stream as a byte stream. The mutex only makes it `Sync`, as
/// the connector's streams must be; it is never locked, since every use
/// holds `&mut`.
// VIPER-PATCH(h2-proxy-addresses): with the addresses of the socket to the
// proxy.
pub(crate) struct H2Tunnel(Mutex<Upgraded>, Option<HttpInfo>);

impl H2Tunnel {
    fn stream(self: Pin<&mut Self>) -> Pin<&mut Upgraded> {
        Pin::new(
            self.get_mut()
                .0
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }
}

impl AsyncRead for H2Tunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.stream().poll_read(cx, buf)
    }
}

impl AsyncWrite for H2Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stream().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream().poll_shutdown(cx)
    }
}

impl Connection for H2Tunnel {
    // VIPER-PATCH(h2-proxy-addresses): the addresses of the socket to the
    // proxy, as an HTTP/1.1 tunnel gives its socket's, so a caller learns
    // which source port the tunnel holds; never the proxy's ALPN, which is
    // not the tunnel's.
    fn connected(&self) -> Connected {
        // VIPER-PATCH(h2-proxy-addresses): the socket's addresses.
        match &self.1 {
            Some(info) => Connected::new().extra(info.clone()),
            None => Connected::new(),
        }
    }
}

impl TlsInfoFactory for H2Tunnel {}

impl fmt::Debug for H2Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("H2Tunnel")
    }
}
