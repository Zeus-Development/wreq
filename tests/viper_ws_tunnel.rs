//! VIPER-PATCH(ws-tunnel): fork tests. A loopback HTTP proxy records each
//! connection's request heads: it answers a `CONNECT` with 200 and then
//! answers the request that comes through the tunnel, or answers a
//! forwarded request at once. `force_tunnel` makes an `http` request
//! tunnel, in origin form and without the proxy's credentials, keyed apart
//! from a forwarded one.

use std::sync::{Arc, Mutex};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use wreq::Client;

/// Reads a request head up to its blank line; empty at end of stream.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if stream.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

const ANSWER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// Serves one proxy connection, pushing its heads, as one list, to `seen`.
async fn serve(mut stream: TcpStream, seen: Arc<Mutex<Vec<Vec<String>>>>) {
    let index = {
        let mut seen = seen.lock().unwrap();
        seen.push(Vec::new());
        seen.len() - 1
    };
    loop {
        let head = read_head(&mut stream).await;
        if head.is_empty() {
            return;
        }
        let connect = head.starts_with("CONNECT ");
        seen.lock().unwrap()[index].push(head);
        let answer: &[u8] = if connect {
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        } else {
            ANSWER
        };
        stream.write_all(answer).await.unwrap();
    }
}

/// The heads each proxy connection carried for GETs of
/// `http://origin.test/`, one per entry of `forced`, calling
/// `force_tunnel` with its value or, for `None`, not at all, through a
/// recording proxy with credentials.
async fn heads(forced: &[Option<bool>]) -> Vec<Vec<String>> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream, Arc::clone(&shared)));
        }
    });
    let proxy = wreq::Proxy::all(&url).unwrap().basic_auth("route", "own");
    let client = Client::builder().proxy(proxy).build().unwrap();
    for &force in forced {
        let mut request = client.get("http://origin.test/");
        if let Some(force) = force {
            request = request.force_tunnel(force);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");
    }
    let seen = seen.lock().unwrap();
    seen.clone()
}

fn line(head: &str) -> &str {
    head.lines().next().unwrap()
}

#[tokio::test]
async fn a_forced_tunnel_carries_an_http_request_in_origin_form() {
    let heads = heads(&[Some(true)]).await;
    assert_eq!(heads.len(), 1);
    let [connect, request] = &heads[0][..] else {
        panic!("{heads:?}");
    };
    assert_eq!(line(connect), "CONNECT origin.test:80 HTTP/1.1");
    let connect_lower = connect.to_ascii_lowercase();
    assert!(connect_lower.contains("proxy-authorization: basic "), "{connect}");
    assert_eq!(line(request), "GET / HTTP/1.1");
    assert!(!request.to_ascii_lowercase().contains("proxy-authorization"), "{request}");
}

#[tokio::test]
async fn without_it_an_http_request_is_forwarded_on_its_own_connection() {
    let heads = heads(&[Some(false), Some(true), Some(false)]).await;
    assert_eq!(heads.len(), 2, "{heads:?}");
    let forwarded = &heads[0];
    assert_eq!(forwarded.len(), 2, "{forwarded:?}");
    for head in forwarded {
        assert_eq!(line(head), "GET http://origin.test/ HTTP/1.1");
    }
    assert_eq!(line(&heads[1][0]), "CONNECT origin.test:80 HTTP/1.1");
    assert_eq!(heads[1].len(), 2, "{heads:?}");
}

// The ws-tunnel follow-up of WREQ-FORK-3's review: `force_tunnel(false)`
// alone sets no tunnel fields, so its request pools with one that never
// called it.
#[tokio::test]
async fn force_tunnel_false_alone_pools_with_a_request_that_never_called_it() {
    let heads = heads(&[None, Some(false), None]).await;
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert_eq!(heads[0].len(), 3, "{heads:?}");
    for head in &heads[0] {
        assert_eq!(line(head), "GET http://origin.test/ HTTP/1.1");
    }
}
