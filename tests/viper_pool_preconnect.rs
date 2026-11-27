//! VIPER-PATCH(pool-preconnect): fork tests, and those of
//! VIPER-PATCH(grouped-preconnect). A loopback HTTP/1.1 server
//! answers every request with the index of the connection it came on (from
//! 0, in accept order), its body a moment after its head, and counts the connections it accepted; connections
//! opened ahead of the requests serve them, within the pool's limits and
//! through the proxy chosen for the URI.

use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use http::Uri;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use wreq::{Client, Group, Proxy};

/// A server's base URL and the count of connections it accepted.
async fn server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(serve(stream, count.fetch_add(1, Ordering::SeqCst)));
        }
    });
    (url, accepted)
}

async fn serve(mut stream: TcpStream, index: usize) {
    let body = index.to_string();
    let head_answer = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while stream.read(&mut byte).await.unwrap_or(0) == 1 {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            head.clear();
            stream.write_all(head_answer.as_bytes()).await.unwrap();
            // The connection stays busy until the body is read.
            tokio::time::sleep(Duration::from_millis(300)).await;
            stream.write_all(body.as_bytes()).await.unwrap();
        }
    }
}

/// The connections that serve `count` requests to `url`, each sent once the
/// earlier ones' heads arrived and before their bodies did, so that none of
/// their connections is idle.
async fn connections(client: &Client, url: &str, count: usize) -> Vec<String> {
    let mut responses = Vec::new();
    for _ in 0..count {
        responses.push(client.get(url).send().await.unwrap());
    }
    let mut connections = Vec::new();
    for response in responses {
        connections.push(response.text().await.unwrap());
    }
    connections.sort();
    connections
}

/// Two connections opened ahead serve the next two requests, sent while
/// both are busy; no other connection is made.
#[tokio::test]
async fn preconnected_connections_serve_later_requests() {
    let (url, accepted) = server().await;
    let client = Client::builder().no_proxy().build().unwrap();
    let outcomes = client.preconnect(url.parse().unwrap(), 2, None).await;
    assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    assert_eq!(connections(&client, &url, 2).await, ["0", "1"]);
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

/// The pool keeps at most `pool_max_idle_per_host` of them: the other is
/// closed, and a second request while the first is busy makes a new
/// connection.
#[tokio::test]
async fn the_pools_idle_limit_holds() {
    let (url, accepted) = server().await;
    let client = Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(1)
        .build()
        .unwrap();
    let outcomes = client.preconnect(url.parse().unwrap(), 2, None).await;
    assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
    let served = connections(&client, &url, 2).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
    assert_eq!(served[1], "2");
}

/// A connection takes the proxy chosen for the URI: the proxy's connection
/// serves the later request to an origin no resolver knows.
#[tokio::test]
async fn a_preconnect_goes_through_the_proxy_chosen_for_the_uri() {
    let (proxy, accepted) = server().await;
    let client = Client::builder()
        .proxy(Proxy::http(&proxy).unwrap())
        .build()
        .unwrap();
    let origin = "http://origin.invalid/";
    let outcomes = client.preconnect(origin.parse().unwrap(), 1, None).await;
    assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
    assert_eq!(connections(&client, origin, 1).await, ["0"]);
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

/// Each connection reports its failure, as a request's connect error; a URI
/// that is not absolute fails each too.
#[tokio::test]
async fn each_connection_reports_its_failure() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let closed = format!("http://{}/", listener.local_addr().unwrap());
    drop(listener);
    let client = Client::builder().no_proxy().build().unwrap();
    let outcomes = client.preconnect(closed.parse().unwrap(), 2, None).await;
    assert_eq!(outcomes.len(), 2);
    for outcome in outcomes {
        let error = outcome.unwrap_err();
        assert!(error.is_connect(), "{error:?}");
        assert_eq!(error.uri().map(Uri::to_string), Some(closed.clone()));
    }
    let relative = client.preconnect(Uri::from_static("/path"), 1, None).await;
    assert!(relative[0].is_err(), "{relative:?}");
}

// VIPER-PATCH(grouped-preconnect)
/// A connection opened ahead in a group serves only a request of that
/// group: another group's request, and one of no group, each make their
/// own.
#[tokio::test]
async fn a_grouped_connection_serves_only_its_group() {
    let (url, accepted) = server().await;
    let client = Client::builder().no_proxy().build().unwrap();
    let group = || Some(Group::new("a"));
    let outcomes = client.preconnect(url.parse().unwrap(), 1, group()).await;
    assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
    let other = client.get(&url).group(Group::new("b")).send().await;
    assert_eq!(other.unwrap().text().await.unwrap(), "1");
    let none = client.get(&url).send().await.unwrap();
    assert_eq!(none.text().await.unwrap(), "2");
    let own = client.get(&url).group(Group::new("a")).send().await;
    assert_eq!(own.unwrap().text().await.unwrap(), "0");
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
}
