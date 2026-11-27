// VIPER-PATCH(h2-informational): the HTTP/2 client hands each interim (1xx)
// response to the request's `on_informational` callback, in the order
// received and before the final response, as the HTTP/1 client does; a
// request without a callback gets its final response as before.

mod support;

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Empty;
use support::rt::TokioExecutor;
use tokio::io::DuplexStream;
use wreq_proto::conn::http2;

const STYLE: &str = "</a.css>; rel=preload; as=style";
const SCRIPT: &str = "</b.js>; rel=preload; as=script";

/// A server that answers one request with a `103 Early Hints` per link of
/// `hints`, then `200 OK`.
async fn serve(io: DuplexStream, hints: &'static [&'static str]) {
    let mut conn = ::http2::server::handshake(io).await.expect("server handshake");
    let (_request, mut respond) = conn
        .accept()
        .await
        .expect("a request")
        .expect("request headers");
    for link in hints {
        let hint = Response::builder()
            .status(StatusCode::EARLY_HINTS)
            .header("link", *link)
            .body(())
            .expect("a 103");
        respond.send_informational(hint).expect("103 sent");
    }
    let ok = Response::builder().status(StatusCode::OK).body(()).expect("a 200");
    respond.send_response(ok, true).expect("200 sent");
    // Drive the connection until the client closes it.
    while conn.accept().await.is_some() {}
}

/// Sends one GET over a new HTTP/2 connection to a server sending `hints`,
/// with a callback recording each interim response when `listen`.
async fn get(hints: &'static [&'static str], listen: bool) -> (StatusCode, Vec<(u16, String)>) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(serve(server_io, hints));
    let (mut client, conn) = http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Empty<Bytes>>(client_io)
        .await
        .expect("client handshake");
    tokio::spawn(conn);

    let heard = Arc::new(Mutex::new(Vec::new()));
    let mut req = Request::get("http://example.test/").body(Empty::new()).expect("a GET");
    if listen {
        let heard = Arc::clone(&heard);
        wreq_proto::ext::on_informational(&mut req, move |res| {
            let link = res.headers()["link"].to_str().expect("a link").to_owned();
            heard.lock().expect("unpoisoned").push((res.status().as_u16(), link));
        });
    }
    let res = client.try_send_request(req).await.expect("a response");
    let heard = heard.lock().expect("unpoisoned").clone();
    (res.status(), heard)
}

#[tokio::test]
async fn h2_interim_responses_reach_the_callback_in_order() {
    let (status, heard) = get(&[STYLE, SCRIPT], true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(heard, vec![(103, STYLE.to_owned()), (103, SCRIPT.to_owned())]);
}

#[tokio::test]
async fn h2_without_a_callback_the_final_response_comes_as_before() {
    let (status, heard) = get(&[STYLE, SCRIPT], false).await;
    assert_eq!(status, StatusCode::OK);
    assert!(heard.is_empty());
}

#[tokio::test]
async fn h2_a_response_without_interim_ones_calls_nothing() {
    let (status, heard) = get(&[], true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(heard.is_empty());
}
