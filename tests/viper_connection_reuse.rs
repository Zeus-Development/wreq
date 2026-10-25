//! VIPER-PATCH(connection-reuse): fork tests. A loopback HTTP/1.1 origin
//! answers or closes each request as its script says and counts the
//! connections it accepted; a failed request says whether its connection
//! was reused, and a request may ask for a new connection.

use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use wreq::Client;

const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";

/// An origin whose `answers(n)` says whether the `n`th request it reads
/// (from 0, over all connections) is answered; an unanswered one closes its
/// connection before any response byte. Returns its base URL and the count
/// of accepted connections.
async fn origin(answers: fn(usize) -> bool) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve(stream, Arc::clone(&requests), answers));
        }
    });
    (url, accepted)
}

async fn serve(mut stream: TcpStream, requests: Arc<AtomicUsize>, answers: fn(usize) -> bool) {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    loop {
        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
        if !head.ends_with(b"\r\n\r\n") {
            continue;
        }
        head.clear();
        if !answers(requests.fetch_add(1, Ordering::SeqCst)) {
            return;
        }
        stream.write_all(OK).await.unwrap();
    }
}

/// A request on a pooled connection that the peer closes before any
/// response byte is reported as sent on a reused connection.
#[tokio::test]
async fn a_failure_on_a_pooled_connection_says_it_was_reused() {
    let (url, accepted) = origin(|n| n == 0).await;
    let client = Client::builder().no_proxy().build().unwrap();
    let first = client.get(&url).send().await.unwrap();
    assert_eq!(first.bytes().await.unwrap().as_ref(), b"ok");
    let error = client.get(&url).send().await.unwrap_err();
    assert!(error.is_connection_reused(), "{error:?}");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

/// The same failure on a connection made for the request is not reused.
#[tokio::test]
async fn a_failure_on_a_new_connection_says_it_was_not_reused() {
    let (url, _) = origin(|_| false).await;
    let client = Client::builder().no_proxy().build().unwrap();
    let error = client.get(&url).send().await.unwrap_err();
    assert!(!error.is_connection_reused(), "{error:?}");
}

/// A request that asks for a new connection gets one although an idle
/// connection is pooled, and that connection joins the pool.
#[tokio::test]
async fn a_request_may_ask_for_a_new_connection() {
    let (url, accepted) = origin(|_| true).await;
    let client = Client::builder().no_proxy().build().unwrap();
    for new_connection in [false, false, true, false] {
        let response = client
            .get(&url)
            .new_connection(new_connection)
            .send()
            .await
            .unwrap();
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"ok");
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

/// Once its pooled connection failed, the request sent again on a new
/// connection succeeds.
#[tokio::test]
async fn a_request_sent_again_on_a_new_connection_succeeds() {
    let (url, accepted) = origin(|n| n != 1).await;
    let client = Client::builder().no_proxy().build().unwrap();
    client
        .get(&url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let error = client.get(&url).send().await.unwrap_err();
    assert!(error.is_connection_reused(), "{error:?}");
    let again = client.get(&url).new_connection(true).send().await.unwrap();
    assert_eq!(again.bytes().await.unwrap().as_ref(), b"ok");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}
