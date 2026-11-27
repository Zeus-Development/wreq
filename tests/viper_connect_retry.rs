//! VIPER-PATCH(connect-407-retry): fork tests. A loopback HTTP proxy answers
//! a `CONNECT` without `Proxy-Authorization` with a 407 and one with it with
//! 200, then serves the tunnelled request itself. A 407 that keeps its
//! connection open gives it back on the failure, and the retry with
//! credentials goes on it; any other 407 keeps nothing; the connection is
//! closed when its handle is dropped, or 30 seconds after the 407.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use http::{HeaderMap, HeaderValue};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use wreq::{Client, ProxyConnection, ProxyFailure};

const CHALLENGE: &str = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                         Proxy-Authenticate: Basic realm=\"retry\"\r\n\
                         Content-Length: 5\r\n\r\nnope!";

/// Reads a head up to its blank line; `None` at the end of the stream.
async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    Some(String::from_utf8(head).unwrap())
}

/// The proxy's record: each `CONNECT` head with its connection's number,
/// and each connection's number as it closes.
struct Proxy {
    url: String,
    heads: Arc<Mutex<Vec<(usize, String)>>>,
    closed: mpsc::UnboundedReceiver<usize>,
}

/// One connection: a challenge without credentials, else 200 and one
/// request served; the connection's end is reported. With `closing`, the
/// first connection closes right after its challenge.
async fn serve(mut stream: TcpStream, number: usize, (challenge, closing, proxy): Serving) {
    while let Some(head) = read_head(&mut stream).await {
        let authorized = head.to_ascii_lowercase().contains("proxy-authorization");
        proxy.0.lock().unwrap().push((number, head));
        if !authorized {
            stream.write_all(challenge.as_bytes()).await.unwrap();
            if closing && number == 0 {
                stream.shutdown().await.unwrap();
                break;
            }
            continue;
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        read_head(&mut stream).await;
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        stream.write_all(answer).await.unwrap();
    }
    let _ = proxy.1.send(number);
}

type Record = (
    Arc<Mutex<Vec<(usize, String)>>>,
    mpsc::UnboundedSender<usize>,
);

type Serving = (&'static str, bool, Record);

async fn proxy(challenge: &'static str) -> Proxy {
    proxy_closing(challenge, false).await
}

/// A proxy whose first connection closes after its challenge when
/// `closing`.
async fn proxy_closing(challenge: &'static str, closing: bool) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let heads = Arc::<Mutex<Vec<_>>>::default();
    let (sender, closed) = mpsc::unbounded_channel();
    let record = (Arc::clone(&heads), sender);
    tokio::spawn(async move {
        let mut number = 0;
        while let Ok((stream, _)) = listener.accept().await {
            let record = (Arc::clone(&record.0), record.1.clone());
            tokio::spawn(serve(stream, number, (challenge, closing, record)));
            number += 1;
        }
    });
    Proxy { url, heads, closed }
}

fn client(proxy: &Proxy) -> Client {
    let config = wreq::Proxy::all(&proxy.url).unwrap();
    Client::builder().proxy(config).build().unwrap()
}

fn credentials() -> HeaderMap {
    let value = HeaderValue::from_static("Basic dXNlcjpwYXNz");
    HeaderMap::from_iter([(http::header::PROXY_AUTHORIZATION, value)])
}

fn proxy_failure(error: &wreq::Error) -> &ProxyFailure {
    let top: &(dyn std::error::Error + 'static) = error;
    let mut chain = std::iter::successors(Some(top), |&e| e.source());
    let found = chain.find_map(|e| e.downcast_ref::<ProxyFailure>());
    found.expect("a ProxyFailure in the chain")
}

/// The connection the 407 to a tunnel to `host` left open, if any.
async fn challenged(client: &Client, host: &str) -> Option<ProxyConnection> {
    let url = format!("http://{host}/");
    let sent = client.get(url).force_tunnel(true).send().await;
    proxy_failure(&sent.unwrap_err()).connection()
}

/// A tunnel to `host` with credentials, on `kept`; its body.
async fn retry(client: &Client, host: &str, kept: ProxyConnection) -> String {
    let url = format!("http://{host}/");
    let request = client.get(url).force_tunnel(true);
    let request = request
        .connect_headers(credentials())
        .proxy_connection(kept);
    request.send().await.unwrap().text().await.unwrap()
}

fn connections(proxy: &Proxy) -> Vec<usize> {
    let heads = proxy.heads.lock().unwrap();
    heads.iter().map(|(number, _)| *number).collect()
}

#[tokio::test]
async fn the_retry_goes_on_the_connection_the_407_came_on() {
    let proxy = proxy(CHALLENGE).await;
    let client = client(&proxy);
    let kept = challenged(&client, "origin.test").await;
    let kept = kept.expect("the 407 keeps its connection");
    assert_eq!(retry(&client, "origin.test", kept).await, "ok");
    assert_eq!(connections(&proxy), [0, 0], "the 407's body read first");
}

#[tokio::test]
async fn a_407_that_may_close_keeps_no_connection() {
    for challenge in [
        "HTTP/1.1 407 No\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 407 No\r\nConnection: keep-alive, Close\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 407 No\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 407 No\r\nContent-Length: 65537\r\n\r\n",
        "HTTP/1.1 407 No\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 407 No\r\nProxy-Connection: close\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 407 No\r\nContent-Length: +0\r\n\r\n",
        // More than the body: the proxy sent a byte after it.
        "HTTP/1.1 407 No\r\nContent-Length: 0\r\n\r\nX",
        "HTTP/1.1 407 No\r\n\r\n",
        "HTTP/1.0 407 No\r\nContent-Length: 0\r\n\r\n",
    ] {
        let proxy = proxy(challenge).await;
        let kept = challenged(&client(&proxy), "origin.test").await;
        assert!(kept.is_none(), "{challenge}");
    }
}

#[tokio::test]
async fn a_connection_kept_for_another_tunnel_is_not_taken() {
    let proxy = proxy(CHALLENGE).await;
    let client = client(&proxy);
    let kept = challenged(&client, "origin.test").await.unwrap();
    assert_eq!(retry(&client, "other.test", kept.clone()).await, "ok");
    let other = proxy_two(&proxy).await;
    assert_eq!(retry(&other, "origin.test", kept.clone()).await, "ok");
    assert_eq!(connections(&proxy), [0, 1, 2]);
    // Still kept for its own tunnel.
    assert_eq!(retry(&client, "origin.test", kept).await, "ok");
    assert_eq!(connections(&proxy), [0, 1, 2, 0]);
}

/// A client through the same proxy with credentials of its own: another
/// proxy entry, so another key.
async fn proxy_two(proxy: &Proxy) -> Client {
    let config = wreq::Proxy::all(&proxy.url).unwrap();
    let config = config.basic_auth("route", "own");
    Client::builder().proxy(config).build().unwrap()
}

#[tokio::test]
async fn a_kept_connection_the_proxy_closed_is_not_taken() {
    let mut proxy = proxy_closing(CHALLENGE, true).await;
    let client = client(&proxy);
    let kept = challenged(&client, "origin.test").await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(10), proxy.closed.recv());
    assert_eq!(closed.await.unwrap(), Some(0));
    // The end of the stream reaches the client's socket.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(retry(&client, "origin.test", kept).await, "ok");
    assert_eq!(connections(&proxy), [0, 1], "a new connection");
}

#[tokio::test]
async fn a_dropped_handle_closes_the_connection() {
    let mut proxy = proxy(CHALLENGE).await;
    let kept = challenged(&client(&proxy), "origin.test").await;
    assert!(kept.is_some());
    drop(kept);
    let closed = tokio::time::timeout(Duration::from_secs(10), proxy.closed.recv());
    assert_eq!(closed.await.unwrap(), Some(0));
}

#[tokio::test(start_paused = true)]
async fn an_unused_connection_closes_30_seconds_after_the_407() {
    let mut proxy = proxy(CHALLENGE).await;
    let start = tokio::time::Instant::now();
    let kept = challenged(&client(&proxy), "origin.test").await;
    assert!(kept.is_some());
    tokio::time::sleep(Duration::from_secs(29)).await;
    assert!(proxy.closed.try_recv().is_err(), "open at 29 s");
    assert_eq!(proxy.closed.recv().await, Some(0));
    assert!(start.elapsed() >= Duration::from_secs(30));
    drop(kept);
}
