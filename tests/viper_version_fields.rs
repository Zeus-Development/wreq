//! VIPER-PATCH(version-fields): fork tests. A loopback server speaking
//! HTTP/1.1 and HTTP/2 (prior knowledge) answers each request with the
//! values of its `priority` field, or the names of its `x-` and `priority`
//! fields in order; a field given for some versions only stays on the heads
//! of connections of those versions, the others keeping their order.

mod support;

use http::{HeaderMap, HeaderValue, Version};
use support::server;
use wreq::{Body, Client};

/// The server, answering with the request's `priority` values joined by `,`.
fn echo() -> server::Server {
    server::http(|request| async move {
        let values: Vec<&str> = (request.headers().get_all("priority").iter())
            .map(|value| value.to_str().unwrap())
            .collect();
        http::Response::new(Body::from(values.join(",")))
    })
}

fn priority(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("priority", HeaderValue::from_static(value));
    headers
}

/// The `priority` values `client` sends to `url` with `versions`' field.
async fn sent(client: &Client, url: &str, own: HeaderMap, versions: &[Version]) -> String {
    let builder = client.get(url).headers(own);
    let builder = builder.version_fields(versions, priority("u=0"));
    builder.send().await.unwrap().text().await.unwrap()
}

/// A field for HTTP/2 only goes on an HTTP/2 head, not on an HTTP/1.1 one.
#[tokio::test]
async fn a_field_goes_only_on_a_connection_of_a_listed_version() {
    let server = echo();
    let url = format!("http://{}/", server.addr());
    let h1 = Client::builder().no_proxy().http1_only().build().unwrap();
    let h2 = Client::builder().no_proxy().http2_only().build().unwrap();
    let only_h2 = &[Version::HTTP_2];
    assert_eq!(sent(&h2, &url, HeaderMap::new(), only_h2).await, "u=0");
    assert_eq!(sent(&h1, &url, HeaderMap::new(), only_h2).await, "");
    let both = &[Version::HTTP_11, Version::HTTP_2];
    assert_eq!(sent(&h1, &url, HeaderMap::new(), both).await, "u=0");
}

/// The listed fields own their names: one set otherwise is replaced on a
/// listed version and left out on another.
#[tokio::test]
async fn the_fields_replace_their_names() {
    let server = echo();
    let url = format!("http://{}/", server.addr());
    let h1 = Client::builder().no_proxy().http1_only().build().unwrap();
    let h2 = Client::builder().no_proxy().http2_only().build().unwrap();
    let only_h2 = &[Version::HTTP_2];
    assert_eq!(sent(&h2, &url, priority("i"), only_h2).await, "u=0");
    assert_eq!(sent(&h1, &url, priority("i"), only_h2).await, "");
}

/// Without them a request is unchanged on either version.
#[tokio::test]
async fn without_them_nothing_changes() {
    let server = echo();
    let url = format!("http://{}/", server.addr());
    for client in [
        Client::builder().no_proxy().http1_only().build().unwrap(),
        Client::builder().no_proxy().http2_only().build().unwrap(),
    ] {
        let response = client.get(&url).headers(priority("i")).send().await;
        assert_eq!(response.unwrap().text().await.unwrap(), "i");
    }
}

/// The server, answering with the request's `x-` and `priority` field names
/// in their order.
fn names() -> server::Server {
    server::http(|request| async move {
        let names: Vec<&str> = (request.headers().keys())
            .map(|name| name.as_str())
            .filter(|name| name.starts_with("x-") || *name == "priority")
            .collect();
        http::Response::new(Body::from(names.join(",")))
    })
}

/// The field keeps its place among the others where it stays, and the
/// others keep their order where it is taken out.
#[tokio::test]
async fn the_order_of_the_fields_holds() {
    let server = names();
    let url = format!("http://{}/", server.addr());
    let mut head = HeaderMap::new();
    for name in ["x-a", "priority", "x-b", "x-c"] {
        head.insert(name, HeaderValue::from_static("1"));
    }
    for (client, expected) in [
        (Client::builder().no_proxy().http2_only(), "x-a,priority,x-b,x-c"),
        (Client::builder().no_proxy().http1_only(), "x-a,x-b,x-c"),
    ] {
        let client = client.build().unwrap();
        let builder = client.get(&url).headers(head.clone());
        let builder = builder.version_fields(&[Version::HTTP_2], priority("u=0"));
        let response = builder.send().await.unwrap();
        assert_eq!(response.text().await.unwrap(), expected);
    }
}
