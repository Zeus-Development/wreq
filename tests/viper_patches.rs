//! VIPER-PATCH(typed-proxy-errors): fork tests. Loopback proxies fail in
//! each way, and the error's source chain holds a `ProxyFailure` of that
//! kind.

use std::io;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use wreq::{Client, ProxyFailure, ProxyFailureKind, StatusCode};

/// A proxy on a loopback port that serves one connection with `serve`.
async fn proxy<F, Fut>(serve: F) -> String
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve(stream).await;
    });
    format!("127.0.0.1:{port}")
}

/// The failure of a GET of `url` through the proxy at `proxy`, and the
/// first I/O error kind below it.
async fn failure(proxy: &str, url: &str) -> (ProxyFailureKind, Option<io::ErrorKind>) {
    let client = Client::builder()
        .proxy(wreq::Proxy::all(proxy).unwrap())
        .build()
        .unwrap();
    let error = client.get(url).send().await.unwrap_err();
    assert!(error.is_proxy_connect(), "{error:?}");
    let top: &(dyn std::error::Error + 'static) = &error;
    let chain = || std::iter::successors(Some(top), |&e| e.source());
    let found = chain().find_map(|e| e.downcast_ref::<ProxyFailure>());
    let kind = found.expect("a ProxyFailure in the chain").kind();
    let io = chain().find_map(|e| e.downcast_ref::<io::Error>().map(io::Error::kind));
    (kind, io)
}

/// Reads a request head up to its blank line.
async fn read_head(stream: &mut TcpStream) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if stream.read(&mut byte).await.unwrap() == 0 {
            return;
        }
        head.push(byte[0]);
    }
}

async fn refusing(status: &'static str) -> String {
    let address = proxy(move |mut stream| async move {
        read_head(&mut stream).await;
        let reply = format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\n\r\n");
        stream.write_all(reply.as_bytes()).await.unwrap();
    });
    format!("http://{}", address.await)
}

#[tokio::test]
async fn a_refused_connect_keeps_its_status() {
    for (status, code) in [
        ("403 Forbidden", 403),
        ("502 Bad Gateway", 502),
        ("407 Proxy", 407),
    ] {
        let (kind, _) = failure(&refusing(status).await, "https://origin.test/").await;
        let expected = StatusCode::from_u16(code).unwrap();
        assert_eq!(kind, ProxyFailureKind::Status(expected), "{status}");
    }
}

#[tokio::test]
async fn a_proxy_that_closes_before_its_reply_is_closed() {
    let address = proxy(|mut stream| async move { read_head(&mut stream).await }).await;
    let (kind, _) = failure(&format!("http://{address}"), "https://origin.test/").await;
    assert_eq!(kind, ProxyFailureKind::Closed);
}

#[tokio::test]
async fn a_failed_connection_to_the_proxy_keeps_its_io_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    for url in ["https://origin.test/", "http://origin.test/"] {
        let (kind, io) = failure(&format!("http://{address}"), url).await;
        assert_eq!(kind, ProxyFailureKind::Connect, "{url}");
        assert_eq!(io, Some(io::ErrorKind::ConnectionRefused), "{url}");
    }
    #[cfg(feature = "socks")]
    {
        let (kind, io) = failure(&format!("socks5h://{address}"), "http://origin.test/").await;
        assert_eq!(kind, ProxyFailureKind::Connect);
        assert_eq!(io, Some(io::ErrorKind::ConnectionRefused));
    }
}

#[tokio::test]
async fn a_malformed_connect_reply_is_malformed() {
    let address = proxy(|mut stream| async move {
        read_head(&mut stream).await;
        stream.write_all(b"HTTP/1.1 2x0 OK\r\n\r\n").await.unwrap();
    });
    let (kind, _) = failure(&format!("http://{}", address.await), "https://origin.test/").await;
    assert_eq!(kind, ProxyFailureKind::Malformed);
}

/// A SOCKS5 proxy (RFC 1928) that answers the greeting with `method` and,
/// for method 0, the request with reply `code`; for method 2 the password
/// sub-negotiation (RFC 1929) with `code`.
#[cfg(feature = "socks")]
async fn socks5(method: u8, code: u8) -> String {
    let address = proxy(move |mut stream| async move {
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        let mut methods = vec![0; usize::from(greeting[1])];
        stream.read_exact(&mut methods).await.unwrap();
        stream.write_all(&[5, method]).await.unwrap();
        if method == 2 {
            let mut auth = [0; 64];
            let _ = stream.read(&mut auth).await.unwrap();
            stream.write_all(&[1, code]).await.unwrap();
            return;
        }
        let mut request = [0; 512];
        let _ = stream.read(&mut request).await.unwrap();
        let reply = [5, code, 0, 1, 127, 0, 0, 1, 0, 80];
        stream.write_all(&reply).await.unwrap();
    });
    address.await
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn each_socks5_reply_code_is_kept() {
    for code in 1..=8 {
        let proxy = format!("socks5h://{}", socks5(0, code).await);
        let (kind, _) = failure(&proxy, "http://origin.test/").await;
        assert_eq!(kind, ProxyFailureKind::Socks5Reply(code), "reply {code}");
    }
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn socks5_authentication_failures_are_typed() {
    let proxy = format!("socks5h://{}", socks5(0xff, 0).await);
    let (kind, _) = failure(&proxy, "http://origin.test/").await;
    assert_eq!(kind, ProxyFailureKind::Socks5NoAcceptableMethods);
    let proxy = format!("socks5h://user:pass@{}", socks5(2, 1).await);
    let (kind, _) = failure(&proxy, "http://origin.test/").await;
    assert_eq!(kind, ProxyFailureKind::Socks5AuthRejected(1));
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn a_socks5_proxy_that_closes_mid_handshake_is_a_handshake_failure() {
    let address = proxy(|mut stream| async move {
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
    });
    let (kind, io) = failure(
        &format!("socks5h://{}", address.await),
        "http://origin.test/",
    )
    .await;
    assert_eq!(kind, ProxyFailureKind::Handshake);
    assert_eq!(io, Some(io::ErrorKind::UnexpectedEof));
}
