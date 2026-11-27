//! VIPER-PATCH(connect-challenge-fields): fork tests. A loopback HTTP proxy
//! answers `CONNECT` with a 407 and its `Proxy-Authenticate` challenge, or
//! with another refusal; the failure keeps the 407's fields only.

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use wreq::{Client, ProxyFailure};

/// Reads a request head up to its blank line.
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

/// A proxy on a loopback port answering each `CONNECT` with `reply`.
async fn refusing(reply: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            read_head(&mut stream).await;
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    format!("http://{address}")
}

/// The fields the failure of a GET of an https URL through `proxy` keeps,
/// as `name: value` lines in order.
async fn kept(proxy: &str) -> Option<Vec<String>> {
    let client = Client::builder()
        .proxy(wreq::Proxy::all(proxy).unwrap())
        .build()
        .unwrap();
    let error = client.get("https://origin.test/").send().await.unwrap_err();
    let top: &(dyn std::error::Error + 'static) = &error;
    let mut chain = std::iter::successors(Some(top), |&e| e.source());
    let failure = chain.find_map(|e| e.downcast_ref::<ProxyFailure>()).unwrap();
    let line = |(name, value): (&http::HeaderName, &http::HeaderValue)| {
        format!("{name}: {}", value.to_str().unwrap())
    };
    failure.headers().map(|fields| fields.iter().map(line).collect())
}

#[tokio::test]
async fn a_407_to_connect_keeps_its_fields() {
    let proxy = refusing(
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         Proxy-Authenticate: Basic realm=\"one\"\r\n\
         Proxy-Authenticate: Digest realm=\"two\"\r\n\
         Content-Length: 0\r\n\r\n",
    )
    .await;
    let fields = kept(&proxy).await.expect("the 407's fields");
    assert_eq!(
        fields,
        [
            "proxy-authenticate: Basic realm=\"one\"",
            "proxy-authenticate: Digest realm=\"two\"",
            "content-length: 0",
        ]
    );
}

#[tokio::test]
async fn another_refusal_keeps_no_fields() {
    let proxy = refusing("HTTP/1.1 403 Forbidden\r\nX-Reason: no\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(kept(&proxy.await).await, None);
}
