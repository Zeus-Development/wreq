//! VIPER-PATCH(connector-layer-identity): fork tests. A connector layer
//! records the URI each connection is made for and gives each a guard that
//! counts the connections still open.

mod support;

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use support::server;
use tower::{BoxError, Layer, Service};
use wreq::{Client, Conn, Unnameable};

/// The URIs of the connections made, and how many are open.
#[derive(Clone, Default)]
struct Seen {
    uris: Arc<Mutex<Vec<String>>>,
    open: Arc<AtomicUsize>,
}

/// Counts one open connection while it lives.
struct Open(Arc<AtomicUsize>);

impl Drop for Open {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct Counting<S>(S, Seen);

impl<S> Layer<S> for Seen {
    type Service = Counting<S>;
    fn layer(&self, inner: S) -> Counting<S> {
        Counting(inner, self.clone())
    }
}

impl<S> Service<Unnameable> for Counting<S>
where
    S: Service<Unnameable, Response = Conn, Error = BoxError>,
    S::Future: Send + 'static,
{
    type Response = Conn;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, target: Unnameable) -> Self::Future {
        let seen = self.1.clone();
        seen.uris.lock().unwrap().push(target.uri().to_string());
        let connecting = self.0.call(target);
        Box::pin(async move {
            let conn = connecting.await?;
            seen.open.fetch_add(1, Ordering::SeqCst);
            Ok(conn.with_guard(Box::new(Open(Arc::clone(&seen.open)))))
        })
    }
}

/// Waits up to a second for `open` to reach `count`.
async fn settles(open: &AtomicUsize, count: usize) -> usize {
    for _ in 0..100 {
        if open.load(Ordering::SeqCst) == count {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    open.load(Ordering::SeqCst)
}

/// The layer reads the connection's URI; its guard lives while the pool
/// keeps the connection and drops when the server closes it.
#[tokio::test]
async fn a_layer_reads_the_uri_and_its_guard_drops_with_the_connection() {
    let server = server::http(|request| async move {
        let close = request.uri().path() == "/close";
        let mut response = http::Response::default();
        if close {
            let value = http::HeaderValue::from_static("close");
            response.headers_mut().insert(http::header::CONNECTION, value);
        }
        response
    });
    let seen = Seen::default();
    let client = Client::builder()
        .no_proxy()
        .connector_layer(seen.clone())
        .build()
        .unwrap();
    let origin = format!("http://{}", server.addr());
    client.get(format!("{origin}/keep")).send().await.unwrap();
    assert_eq!(settles(&seen.open, 1).await, 1, "the pooled one stays open");
    client.get(format!("{origin}/close")).send().await.unwrap();
    assert_eq!(settles(&seen.open, 0).await, 0, "the closed one's guard drops");
    let uris = seen.uris.lock().unwrap().clone();
    assert_eq!(uris, [format!("{origin}/")], "the origin, once");
}

/// A connection the pool does not keep drops its guard once its response
/// is read.
#[tokio::test]
async fn a_connection_the_pool_drops_drops_its_guard() {
    let server = server::http(|_| async { http::Response::default() });
    let seen = Seen::default();
    let client = Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .connector_layer(seen.clone())
        .build()
        .unwrap();
    let url = format!("http://{}/", server.addr());
    let response = client.get(&url).send().await.unwrap();
    response.bytes().await.unwrap();
    assert_eq!(settles(&seen.open, 0).await, 0);
    assert_eq!(seen.uris.lock().unwrap().len(), 1);
}
