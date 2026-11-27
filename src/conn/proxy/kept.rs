//! VIPER-PATCH(connect-407-retry): a connection to an HTTP proxy kept open
//! after its 407 answer to a tunnel's `CONNECT`, so that the caller's retry
//! with credentials goes on the same connection, as a browser's does: RFC
//! 9110 section 15.5.8 lets a client repeat the request with
//! `Proxy-Authorization`, and an HTTP/1.1 connection stays open after a
//! response unless it says otherwise (RFC 9112 section 9.3).

use std::{
    fmt,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll, Waker},
    time::Duration,
};

use http::Uri;
use tokio::io::{AsyncRead, ReadBuf};
use tower::Service;
use wreq_proto::rt::{Executor as _, Timer as _};

use crate::{
    conn::HttpConnector,
    proxy::matcher::Intercept,
    rt::{Executor, Timer},
    tls::conn::MaybeHttpsStream,
};

/// How long a kept connection waits for the retry before it is closed: 30
/// s, under common proxies' idle timeouts (75 s and 120 s), so the proxy
/// rarely closes it first, and far more than a caller answering a challenge
/// at once needs.
pub(crate) const KEPT_FOR: Duration = Duration::from_secs(30);

/// A connection to a proxy, plain or TLS, that a `CONNECT` is written on.
pub(crate) type ProxyStream = MaybeHttpsStream<<HttpConnector as Service<Uri>>::Response>;

/// A connection to an HTTP proxy kept open after the proxy answered a
/// tunnel's `CONNECT` with 407 over HTTP/1.1, taken from the failure
/// ([`ProxyFailure::connection`](crate::ProxyFailure::connection)) and given
/// to the retry ([`RequestBuilder::proxy_connection`](crate::RequestBuilder::proxy_connection)),
/// which writes its `CONNECT` on it when it goes to the same proxy, with the
/// same credentials and fields, for the same authority. Clones share the one
/// connection, which the first such retry takes. It is closed when the last
/// clone is dropped, or 30 seconds after the 407.
#[derive(Clone)]
pub struct ProxyConnection(Arc<Kept>);

/// The stream, and the proxy and `CONNECT` authority it was kept for.
struct Kept {
    proxy: Intercept,
    authority: String,
    stream: Mutex<Option<ProxyStream>>,
}

fn held(kept: &Kept) -> MutexGuard<'_, Option<ProxyStream>> {
    kept.stream.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ProxyConnection {
    /// Keeps `stream`, a connection to `proxy` that a `CONNECT` to
    /// `authority` was answered on, closing it [`KEPT_FOR`] from now if no
    /// retry took it.
    pub(crate) fn new(stream: ProxyStream, proxy: &Intercept, authority: String) -> Self {
        let stream = Mutex::new(Some(stream));
        let kept = Arc::new(Kept {
            proxy: proxy.clone(),
            authority,
            stream,
        });
        let expiring = Arc::downgrade(&kept);
        Executor::default().execute(async move {
            Timer::default().sleep(KEPT_FOR).await;
            if let Some(kept) = expiring.upgrade() {
                drop(held(&kept).take());
            }
        });
        Self(kept)
    }

    /// The kept stream, at most once, for a tunnel through `proxy` to
    /// `authority` only, unless the proxy has closed it or sent anything
    /// since its 407.
    pub(crate) fn take(&self, proxy: &Intercept, authority: &str) -> Option<ProxyStream> {
        let kept = &self.0;
        if kept.proxy != *proxy || kept.authority != authority {
            return None;
        }
        let mut stream = held(kept).take()?;
        let mut byte = [0; 1];
        let mut buf = ReadBuf::new(&mut byte);
        let mut cx = Context::from_waker(Waker::noop());
        match Pin::new(&mut stream).poll_read(&mut cx, &mut buf) {
            Poll::Pending => Some(stream),
            Poll::Ready(_) => None,
        }
    }
}

impl fmt::Debug for ProxyConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyConnection")
    }
}
