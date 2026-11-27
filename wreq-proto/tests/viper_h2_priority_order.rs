// VIPER-PATCH(h2-priority-order): the HTTP/2 client opens the streams of
// the requests it holds most urgent first (RFC 9218 section 4.1), in the
// order sent within an urgency, and so writes their HEADERS in that order
// with ascending stream ids (RFC 9113 section 5.1.1), both for requests
// sent together and for requests waiting at the server's concurrent
// stream limit.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Empty;
use support::rt::TokioExecutor;
use tokio::io::DuplexStream;
use wreq_proto::conn::http2;
use wreq_proto::http2::Urgency;

type Paths = Arc<Mutex<Vec<String>>>;
type Client = http2::SendRequest<Empty<Bytes>>;
type Conn = http2::Connection<DuplexStream, Empty<Bytes>, TokioExecutor>;

/// A server that records each request's path in the order its streams
/// arrive and answers each `200 OK`, the one for `/held` 100 ms late, with
/// at most `max` concurrent streams.
async fn serve(io: DuplexStream, max: u32, paths: Paths) {
    let mut builder = ::http2::server::Builder::new();
    builder.max_concurrent_streams(max);
    let mut conn = builder.handshake::<_, Bytes>(io).await.expect("server handshake");
    while let Some(Ok((request, mut respond))) = conn.accept().await {
        let path = request.uri().path().to_owned();
        paths.lock().expect("unpoisoned").push(path.clone());
        let ok = Response::builder().status(StatusCode::OK).body(()).expect("a 200");
        tokio::spawn(async move {
            if path == "/held" {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            respond.send_response(ok, true).expect("200 sent");
        });
    }
}

fn get(path: &str, urgency: Option<u8>) -> Request<Empty<Bytes>> {
    let uri = format!("http://example.test{path}");
    let mut request = Request::get(uri).body(Empty::new()).expect("a GET");
    if let Some(urgency) = urgency {
        let urgency = Urgency::new(urgency).expect("an urgency");
        request.extensions_mut().insert(urgency);
    }
    request
}

/// The client of a new connection to a server of at most `max` streams,
/// and the paths that server records.
async fn connect(max: u32) -> (Client, Conn, Paths) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let paths = Paths::default();
    tokio::spawn(serve(server_io, max, Arc::clone(&paths)));
    let (client, conn) = http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Empty<Bytes>>(client_io)
        .await
        .expect("client handshake");
    (client, conn, paths)
}

#[tokio::test]
async fn h2_requests_sent_together_open_streams_most_urgent_first() {
    let (mut client, conn, paths) = connect(100).await;
    // All five are held before the connection runs.
    let sent = [
        ("/a", Some(3)),
        ("/b", None),
        ("/c", Some(0)),
        ("/d", Some(7)),
        ("/e", Some(0)),
    ];
    let responses: Vec<_> = sent
        .iter()
        .map(|(path, urgency)| client.try_send_request(get(path, *urgency)))
        .collect();
    tokio::spawn(conn);
    for response in responses {
        assert_eq!(response.await.expect("a response").status(), StatusCode::OK);
    }
    let paths = paths.lock().expect("unpoisoned").clone();
    assert_eq!(paths, ["/c", "/e", "/a", "/b", "/d"]);
}

#[tokio::test]
async fn h2_requests_waiting_at_the_stream_limit_open_most_urgent_first() {
    let (mut client, conn, paths) = connect(1).await;
    tokio::spawn(conn);
    // The first answer brings the server's SETTINGS, its limit of 1.
    let first = client.try_send_request(get("/first", None)).await;
    assert_eq!(first.expect("a response").status(), StatusCode::OK);
    let held = client.try_send_request(get("/held", Some(7)));
    tokio::time::sleep(Duration::from_millis(20)).await;
    let waiting: Vec<_> = [("/low", Some(5)), ("/mid", Some(3)), ("/high", Some(0))]
        .iter()
        .map(|(path, urgency)| client.try_send_request(get(path, *urgency)))
        .collect();
    assert_eq!(held.await.expect("a response").status(), StatusCode::OK);
    for response in waiting {
        assert_eq!(response.await.expect("a response").status(), StatusCode::OK);
    }
    let paths = paths.lock().expect("unpoisoned").clone();
    assert_eq!(paths, ["/first", "/held", "/high", "/mid", "/low"]);
}

#[tokio::test]
async fn h2_requests_without_an_urgency_keep_the_order_sent() {
    let (mut client, conn, paths) = connect(100).await;
    let responses: Vec<_> = ["/1", "/2", "/3"]
        .iter()
        .map(|path| client.try_send_request(get(path, None)))
        .collect();
    tokio::spawn(conn);
    for response in responses {
        assert_eq!(response.await.expect("a response").status(), StatusCode::OK);
    }
    let paths = paths.lock().expect("unpoisoned").clone();
    assert_eq!(paths, ["/1", "/2", "/3"]);
}
