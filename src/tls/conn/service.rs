use std::{
    fmt::Debug,
    // VIPER-PATCH(async-verify-evidence)
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
};

use btls::ssl::ErrorCode; // VIPER-PATCH(async-verify-evidence)
use http::{Uri, uri::Scheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_btls::SslStream;
use tower::{BoxError, Service};

// VIPER-PATCH(verify-hook): the hook's error type.
use super::{EstablishedConn, HttpsConnector, MaybeHttpsStream, TlsConnector};
use crate::{
    conn::{Connection, descriptor::ConnectionDescriptor},
    ext::UriExt,
    tls::verify::CertificateRefused, // VIPER-PATCH(verify-hook)
    tls::verify::Verification,       // VIPER-PATCH(async-verify-evidence)
};

type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

// VIPER-PATCH(verify-hook): a refused certificate keeps the verification
// result, and the caller's hook checks the chain for `uri`'s host before
// the stream is handed out, so before any request byte.
// VIPER-PATCH(async-verify-evidence): the hook runs inside the handshake as
// the library's custom verification, and the handshake waits while its
// answer is pending (`WANT_CERTIFICATE_VERIFY`), woken by that answer.
async fn perform_handshake<T>(
    tls: &TlsConnector,
    // VIPER-PATCH(async-verify-evidence)
    mut ssl: btls::ssl::Ssl,
    conn: T,
    uri: &Uri,
) -> Result<MaybeHttpsStream<T>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // VIPER-PATCH(async-verify-evidence)
    let verification = tls.verify_hook.as_ref().map(|hook| {
        let host = TlsConnector::normalize_host(uri.host().unwrap_or_default());
        Verification::install(hook, &mut ssl, host)
    });
    let mut stream = SslStream::new(ssl, conn)?;
    // VIPER-PATCH(async-verify-evidence)
    let handshake = poll_fn(|cx| {
        if let Some(verification) = &verification {
            verification.set_waker(cx.waker());
        }
        match Pin::new(&mut stream).poll_connect(cx) {
            // VIPER-PATCH(async-verify-evidence)
            Poll::Ready(Err(error))
                if verification.is_some() && error.code() == ErrorCode::WANT_CERTIFICATE_VERIFY =>
            {
                Poll::Pending
            }
            ready => ready,
        }
    })
    .await;
    // VIPER-PATCH(async-verify-evidence): fork review F1: the hook's panic
    // reaches this task, as before the patch.
    if let Some(verification) = &verification {
        verification.resume_panic();
    }
    // VIPER-PATCH(verify-hook): the verification result of a refusal.
    // VIPER-PATCH(async-verify-evidence)
    if let Err(error) = handshake {
        return Err(CertificateRefused::from_handshake(
            stream.ssl(),
            // VIPER-PATCH(async-verify-evidence)
            verification.as_deref(),
            error.into(),
        ));
    }
    // VIPER-PATCH(async-verify-evidence)
    if let Some(verification) = &verification
        && let Some(check) = verification.after_handshake(stream.ssl())?
    {
        check.await?;
    }
    Ok(MaybeHttpsStream::Https(stream))
}

impl<T, S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<T>;
    type Error = BoxError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connect = self.http.call(uri.clone());
        let tls = self.tls.clone();

        let f = async move {
            let conn = connect.await.map_err(Into::into)?;

            // Early return if it is not a tls scheme
            if uri.scheme() != Some(&Scheme::HTTPS) {
                return Ok(MaybeHttpsStream::Http(conn));
            }

            // VIPER-PATCH(verify-hook): the host goes to the hook.
            let ssl = tls.setup_ssl(uri.clone())?;
            perform_handshake(&tls, ssl, conn, &uri).await
        };

        Box::pin(f)
    }
}

impl<T, S> Service<ConnectionDescriptor> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<T>;
    type Error = BoxError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, descriptor: ConnectionDescriptor) -> Self::Future {
        let uri = descriptor.uri().clone();
        let connect = self.http.call(uri.clone());
        let tls = self.tls.clone();

        let f = async move {
            let conn = connect.await.map_err(Into::into)?;

            // Early return if it is not a tls scheme
            if uri.is_http() {
                return Ok(MaybeHttpsStream::Http(conn));
            }

            let ssl = tls.setup_ssl2(descriptor)?;
            // VIPER-PATCH(verify-hook): the host goes to the hook.
            perform_handshake(&tls, ssl, conn, &uri).await
        };

        Box::pin(f)
    }
}

impl<T, S, IO> Service<EstablishedConn<IO>> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send + Clone + 'static,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug + 'static,
{
    type Response = MaybeHttpsStream<IO>;
    type Error = BoxError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, conn: EstablishedConn<IO>) -> Self::Future {
        let tls = self.tls.clone();
        let fut = async move {
            // Early return if it is not a tls scheme
            if conn.descriptor.uri().is_http() {
                return Ok(MaybeHttpsStream::Http(conn.io));
            }

            // VIPER-PATCH(verify-hook): the host goes to the hook.
            let uri = conn.descriptor.uri().clone();
            let ssl = tls.setup_ssl2(conn.descriptor)?;
            // VIPER-PATCH(verify-hook): the host goes to the hook.
            perform_handshake(&tls, ssl, conn.io, &uri).await
        };

        Box::pin(fut)
    }
}
