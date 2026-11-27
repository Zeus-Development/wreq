//! VIPER-PATCH(connect-head-fields): fork tests. A loopback HTTP proxy
//! records each raw `CONNECT` head and refuses it; a request's
//! `connect_order` writes the head's fields, `Host` among them, in its order
//! and case.

use std::sync::{Arc, Mutex};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use wreq::{
    Client,
    header::{HeaderMap, HeaderValue, OrigHeaderMap},
};

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

/// The raw `CONNECT` head a GET of `https://origin.test/` through a
/// recording proxy sends, with `fields` and `order` on the request and
/// `auth` as the proxy's credentials.
async fn head(
    fields: &[(&'static str, &'static str)],
    order: Option<&[&str]>,
    auth: bool,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&heads);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let head = read_head(&mut stream).await;
            seen.lock().unwrap().push(head);
            let refusal = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(refusal).await.unwrap();
        }
    });
    let mut proxy = wreq::Proxy::all(&url).unwrap();
    if auth {
        proxy = proxy.basic_auth("route", "own");
    }
    let client = Client::builder().proxy(proxy).build().unwrap();
    let mut request = client.get("https://origin.test/");
    if !fields.is_empty() {
        let mut map = HeaderMap::new();
        for (name, value) in fields {
            map.append(*name, HeaderValue::from_static(value));
        }
        request = request.connect_headers(map);
    }
    if let Some(order) = order {
        let mut map = OrigHeaderMap::new();
        for name in order {
            map.insert((*name).to_owned());
        }
        request = request.connect_order(map);
    }
    request.send().await.unwrap_err();
    let heads = heads.lock().unwrap();
    assert_eq!(heads.len(), 1);
    heads[0].clone()
}

const CHROME: &[(&str, &str)] = &[
    ("user-agent", "Agent/1"),
    ("proxy-connection", "keep-alive"),
];

#[tokio::test]
async fn the_order_writes_its_fields_in_its_order_and_case() {
    let order: &[&str] = &["Host", "Proxy-Connection", "User-Agent"];
    assert_eq!(
        head(CHROME, Some(order), false).await,
        "CONNECT origin.test:443 HTTP/1.1\r\n\
         Host: origin.test:443\r\n\
         Proxy-Connection: keep-alive\r\n\
         User-Agent: Agent/1\r\n\r\n"
    );
}

#[tokio::test]
async fn host_goes_where_the_order_places_it_or_first() {
    let placed: &[&str] = &["User-Agent", "Host"];
    assert_eq!(
        head(CHROME, Some(placed), false).await,
        "CONNECT origin.test:443 HTTP/1.1\r\n\
         User-Agent: Agent/1\r\n\
         Host: origin.test:443\r\n\
         proxy-connection: keep-alive\r\n\r\n"
    );
    let unplaced: &[&str] = &["Proxy-Connection"];
    assert_eq!(
        head(CHROME, Some(unplaced), true).await,
        "CONNECT origin.test:443 HTTP/1.1\r\n\
         Host: origin.test:443\r\n\
         Proxy-Connection: keep-alive\r\n\
         user-agent: Agent/1\r\n\
         proxy-authorization: Basic cm91dGU6b3du\r\n\r\n"
    );
}

#[tokio::test]
async fn without_an_order_the_head_is_unchanged() {
    assert_eq!(
        head(CHROME, None, true).await,
        "CONNECT origin.test:443 HTTP/1.1\r\n\
         Host: origin.test:443\r\n\
         user-agent: Agent/1\r\n\
         proxy-connection: keep-alive\r\n\
         proxy-authorization: Basic cm91dGU6b3du\r\n\r\n"
    );
    assert_eq!(
        head(&[], None, false).await,
        "CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n"
    );
}
