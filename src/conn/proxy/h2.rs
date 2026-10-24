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
use http::{Method, Request, StatusCode, Uri, header::PROXY_AUTHORIZATION};
use http_body_util::Empty;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower::{BoxError, Service};
use wreq_proto::{
    conn::http2::{Builder, SendRequest},
    rt::Executor as _,
    upgrade::{self, Upgraded},
};

use super::tunnel::TunnelError;
use crate::{
    conn::{Connected, Connection, TlsConn, tls_info::TlsInfoFactory},
    ext::UriExt,
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
pub(crate) type Shared = Arc<Mutex<Vec<(Intercept, SendRequest<Empty<Bytes>>)>>>;

/// A tunnel's first leg: a `CONNECT` stream, or a connection to the proxy
/// that did not select `h2`, for an HTTP/1.1 `CONNECT`.
pub(crate) enum Opened<T> {
    Stream(H2Tunnel),
    Http1(T),
}

/// The tunnel through `proxy` to `dst`'s authority: a stream of the proxy's
/// shared HTTP/2 connection, opened with the proxy's ALPN list if none is
/// open. An error is a [`TunnelError`], as for an HTTP/1.1 tunnel: the
/// connection to the proxy failed, the proxy answered with a status other
/// than 200, or the stream or connection failed (`Io`), for example when the
/// proxy reset the stream.
pub(crate) async fn open<S, T>(
    shared: &Shared,
    proxy: &Intercept,
    alpn: &[AlpnProtocol],
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
    let mut sender = match find(shared, proxy) {
        Some(sender) => sender,
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
            let sender = handshake(TlsConn { stream }).await?;
            let mut list = shared.lock().unwrap_or_else(PoisonError::into_inner);
            list.push((proxy.clone(), sender.clone()));
            sender
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
    let response = sender
        .try_send_request(request)
        .await
        .map_err(|error| failed(error.into_error()))?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::PROXY_AUTHENTICATION_REQUIRED => return Err(TunnelError::ProxyAuthRequired),
        status => return Err(TunnelError::TunnelUnsuccessful(Some(status))),
    }
    let upgraded = upgrade::on(response).await.map_err(failed)?;
    Ok(Opened::Stream(H2Tunnel(Mutex::new(upgraded))))
}

/// A failure of the HTTP/2 connection or stream, after the connection to
/// the proxy was made, as an I/O error of the tunnel's handshake.
fn failed(error: impl Into<BoxError>) -> TunnelError {
    TunnelError::Io(io::Error::other(error))
}

/// A clone of `proxy`'s open connection, after dropping closed ones.
fn find(shared: &Shared, proxy: &Intercept) -> Option<SendRequest<Empty<Bytes>>> {
    let mut list = shared.lock().unwrap_or_else(PoisonError::into_inner);
    list.retain(|(_, sender)| !sender.is_closed());
    let found = list.iter().find(|(key, _)| key == proxy);
    found.map(|(_, sender)| sender.clone())
}

/// The HTTP/2 handshake with the proxy, its connection driven on the
/// runtime's executor, with wreq-proto's default HTTP/2 settings.
async fn handshake<T>(io: T) -> Result<SendRequest<Empty<Bytes>>, TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let exec = Executor::default();
    let (mut sender, conn) = Builder::new(exec.clone())
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
pub(crate) struct H2Tunnel(Mutex<Upgraded>);

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
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl TlsInfoFactory for H2Tunnel {}

impl fmt::Debug for H2Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("H2Tunnel")
    }
}
