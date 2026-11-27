//! VIPER-PATCH(h2-proxy-connect): fork tests, with VIPER-PATCH(proxy-alpn).
//! A loopback HTTPS proxy selects `h2` or `http/1.1` from the client's ALPN
//! list and tunnels to loopback TLS origins: over HTTP/2, each tunnel is a
//! `CONNECT` stream of one shared connection (RFC 9113 section 8.5).

use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use btls::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{AlpnError, Ssl, SslContext, SslMethod, select_next_proto},
    x509::{X509Builder, X509NameBuilder},
};
use bytes::Bytes;
use http_body_util::{Empty, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};
use tokio_btls::SslStream;
use wreq::{Client, ProxyFailure, ProxyFailureKind, tls::AlpnProtocol};

/// The ALPN wire lists a proxy may select from.
const H2_AND_HTTP1: &[u8] = b"\x02h2\x08http/1.1";
const HTTP1_ONLY: &[u8] = b"\x08http/1.1";

/// A self-signed TLS context; the client in these tests does not verify.
fn context(select: &'static [u8], offers: Arc<Mutex<Vec<Vec<u8>>>>) -> SslContext {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key: PKey<Private> = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "loopback")
        .unwrap();
    let name = name.build();
    let mut cert = X509Builder::new().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let mut builder = SslContext::builder(SslMethod::tls()).unwrap();
    builder.set_private_key(&key).unwrap();
    builder.set_certificate(&cert.build()).unwrap();
    builder.set_alpn_select_callback(move |_, client| {
        offers.lock().unwrap().push(client.to_vec());
        select_next_proto(select, client).ok_or(AlpnError::NOACK)
    });
    builder.build()
}

async fn accept_tls(context: &SslContext, stream: TcpStream) -> SslStream<TcpStream> {
    let mut tls = SslStream::new(Ssl::new(context).unwrap(), stream).unwrap();
    Pin::new(&mut tls).accept().await.unwrap();
    tls
}

/// A TLS origin answering every request with its port as the body.
async fn origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let context = context(HTTP1_ONLY, Arc::default());
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let tls = accept_tls(&context, stream).await;
            let answer = service_fn(move |_: Request<Incoming>| async move {
                Ok::<_, io::Error>(Response::new(Full::new(Bytes::from(port.to_string()))))
            });
            let conn = hyper::server::conn::http1::Builder::new();
            tokio::spawn(conn.serve_connection(TokioIo::new(tls), answer));
        }
    });
    port
}

/// What the proxy answers a `CONNECT` to the refused port.
#[derive(Clone, Copy)]
enum Refusal {
    ResetStream,
    Status(StatusCode),
}

/// A loopback HTTPS proxy: its TCP connections, the ALPN lists offered and
/// each `CONNECT`'s `Proxy-Authorization`.
struct Proxy {
    url: String,
    accepted: Arc<AtomicUsize>,
    offers: Arc<Mutex<Vec<Vec<u8>>>>,
    // VIPER-PATCH(request-connect-fields): what each `CONNECT` carried.
    connects: Connects,
    // VIPER-PATCH(connect-head-fields): each `CONNECT`'s field names.
    names: Names,
}

/// Each `CONNECT`'s field names, in order.
type Names = Arc<Mutex<Vec<Vec<String>>>>;

/// Each `CONNECT`'s `Proxy-Authorization` value, in order.
type Connects = Arc<Mutex<Vec<Option<String>>>>;

async fn proxy(select: &'static [u8], refused: Option<(u16, Refusal)>) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let (accepted, offers) = (Arc::new(AtomicUsize::new(0)), Arc::default());
    let context = context(select, Arc::clone(&offers));
    let count = Arc::clone(&accepted);
    let connects = Connects::default();
    let seen = Arc::clone(&connects);
    let names = Names::default();
    let named = Arc::clone(&names);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let tls = accept_tls(&context, stream).await;
            let (seen, named) = (Arc::clone(&seen), Arc::clone(&named));
            if tls.ssl().selected_alpn_protocol() == Some(b"h2".as_slice()) {
                let serve = service_fn(move |request: Request<Incoming>| {
                    let field = request.headers().get("proxy-authorization");
                    let field = field.map(|value| value.to_str().unwrap().to_owned());
                    seen.lock().unwrap().push(field);
                    let keys = request.headers().keys().map(|name| name.to_string());
                    named.lock().unwrap().push(keys.collect());
                    connect(request, refused)
                });
                let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                tokio::spawn(conn.serve_connection(TokioIo::new(tls), serve));
            } else {
                tokio::spawn(connect_http1(tls, seen, named));
            }
        }
    });
    Proxy {
        url,
        accepted,
        offers,
        connects,
        names,
    }
}

/// One HTTP/2 `CONNECT`: a reset (the service's error), a status, or 200
/// and the stream relayed to the target port.
async fn connect(
    request: Request<Incoming>,
    refused: Option<(u16, Refusal)>,
) -> Result<Response<Empty<Bytes>>, io::Error> {
    assert_eq!(request.method(), hyper::Method::CONNECT);
    let port = request.uri().port_u16().unwrap();
    match refused {
        Some((at, Refusal::ResetStream)) if at == port => Err(io::Error::other("refused")),
        Some((at, Refusal::Status(status))) if at == port => {
            let mut response = Response::new(Empty::new());
            *response.status_mut() = status;
            // VIPER-PATCH(connect-challenge-fields): a 407's challenge.
            let challenge = hyper::header::HeaderValue::from_static("Basic realm=\"h2\"");
            response
                .headers_mut()
                .insert("proxy-authenticate", challenge);
            Ok(response)
        }
        _ => {
            tokio::spawn(async move {
                let mut tunnel = TokioIo::new(hyper::upgrade::on(request).await.unwrap());
                let mut target = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                drop(copy_bidirectional(&mut tunnel, &mut target).await);
            });
            Ok(Response::new(Empty::new()))
        }
    }
}

/// One HTTP/1.1 `CONNECT`, answered 200 and relayed.
async fn connect_http1(mut tls: SslStream<TcpStream>, seen: Connects, named: Names) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tls.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap();
    let field = head.lines().find_map(|line| {
        let (name, value) = line.split_once(": ")?;
        name.eq_ignore_ascii_case("proxy-authorization")
            .then(|| value.to_owned())
    });
    seen.lock().unwrap().push(field);
    let lines = head.lines().skip(1).filter_map(|line| line.split_once(": "));
    named.lock().unwrap().push(lines.map(|(name, _)| name.to_owned()).collect());
    let target = head
        .strip_prefix("CONNECT ")
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    let mut target = TcpStream::connect(target).await.unwrap();
    tls.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    drop(copy_bidirectional(&mut tls, &mut target).await);
}

fn client(proxy: &Proxy, alpn: Option<&[AlpnProtocol]>) -> Client {
    let mut config = wreq::Proxy::all(&proxy.url).unwrap();
    if let Some(alpn) = alpn {
        config = config.alpn_protocols(alpn);
    }
    Client::builder()
        .proxy(config)
        .tls_cert_verification(false)
        .build()
        .unwrap()
}

async fn get(client: &Client, port: u16) -> Result<String, wreq::Error> {
    let url = format!("https://127.0.0.1:{port}/");
    client.get(url).send().await?.text().await
}

fn failure(error: &wreq::Error) -> ProxyFailureKind {
    proxy_failure(error).kind()
}

fn proxy_failure(error: &wreq::Error) -> &ProxyFailure {
    let top: &(dyn std::error::Error + 'static) = error;
    let mut chain = std::iter::successors(Some(top), |&e| e.source());
    let found = chain.find_map(|e| e.downcast_ref::<ProxyFailure>());
    found.expect("a ProxyFailure in the chain")
}

/// VIPER-PATCH(connect-challenge-fields): the challenge a 407 kept.
fn challenge(error: &wreq::Error) -> Option<&str> {
    let fields = proxy_failure(error).headers()?;
    fields.get("proxy-authenticate")?.to_str().ok()
}

const BOTH: &[AlpnProtocol] = &[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1];

#[tokio::test]
async fn two_tunnels_are_streams_of_one_http2_connection() {
    let (first, second) = (origin().await, origin().await);
    let proxy = proxy(H2_AND_HTTP1, None).await;
    let client = client(&proxy, Some(BOTH));
    assert_eq!(get(&client, first).await.unwrap(), first.to_string());
    assert_eq!(get(&client, second).await.unwrap(), second.to_string());
    assert_eq!(proxy.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(*proxy.offers.lock().unwrap(), [H2_AND_HTTP1.to_vec()]);
}

#[tokio::test]
async fn a_reset_stream_or_a_status_fails_that_tunnel_only() {
    let (first, refused, last) = (origin().await, origin().await, origin().await);
    for (refusal, kind) in [
        (Refusal::ResetStream, ProxyFailureKind::Handshake),
        (
            Refusal::Status(StatusCode::FORBIDDEN),
            ProxyFailureKind::Status(StatusCode::FORBIDDEN),
        ),
        (
            Refusal::Status(StatusCode::PROXY_AUTHENTICATION_REQUIRED),
            ProxyFailureKind::Status(StatusCode::PROXY_AUTHENTICATION_REQUIRED),
        ),
    ] {
        let proxy = proxy(H2_AND_HTTP1, Some((refused, refusal))).await;
        let client = client(&proxy, Some(BOTH));
        assert!(get(&client, first).await.is_ok());
        let error = get(&client, refused).await.unwrap_err();
        assert!(error.is_proxy_connect(), "{error:?}");
        assert_eq!(failure(&error), kind);
        let is_407 = kind == ProxyFailureKind::Status(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        let kept = is_407.then_some("Basic realm=\"h2\"");
        assert_eq!(challenge(&error), kept);
        assert_eq!(get(&client, last).await.unwrap(), last.to_string());
        assert_eq!(proxy.accepted.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn a_proxy_that_refuses_h2_gets_an_http1_connect() {
    let (first, second) = (origin().await, origin().await);
    let proxy = proxy(HTTP1_ONLY, None).await;
    let client = client(&proxy, Some(BOTH));
    assert_eq!(get(&client, first).await.unwrap(), first.to_string());
    assert_eq!(get(&client, second).await.unwrap(), second.to_string());
    // One connection per HTTP/1.1 tunnel, each offering the list.
    assert_eq!(proxy.accepted.load(Ordering::SeqCst), 2);
    assert_eq!(*proxy.offers.lock().unwrap(), [H2_AND_HTTP1, H2_AND_HTTP1]);
}

#[tokio::test]
async fn without_a_list_no_alpn_is_offered_and_http1_one_is() {
    let first = origin().await;
    let proxy = proxy(H2_AND_HTTP1, None).await;
    assert_eq!(
        get(&client(&proxy, None), first).await.unwrap(),
        first.to_string()
    );
    assert!(proxy.offers.lock().unwrap().is_empty());
    let first = origin().await;
    let only = &[AlpnProtocol::HTTP1];
    assert_eq!(
        get(&client(&proxy, Some(only)), first).await.unwrap(),
        first.to_string()
    );
    assert_eq!(*proxy.offers.lock().unwrap(), [HTTP1_ONLY.to_vec()]);
}

// VIPER-PATCH(request-connect-fields): a request's own `CONNECT` fields
// replace the proxy's credentials on its tunnel only, which serves only
// requests with the same fields, over HTTP/2 and HTTP/1.1 alike.
#[tokio::test]
async fn a_requests_connect_fields_go_on_its_own_tunnel_only() {
    for (select, alpn) in [(H2_AND_HTTP1, BOTH), (HTTP1_ONLY, &[AlpnProtocol::HTTP1][..])] {
        let origin = origin().await;
        let proxy = proxy(select, None).await;
        let config = wreq::Proxy::all(&proxy.url).unwrap();
        let client = Client::builder()
            .proxy(config.basic_auth("route", "own").alpn_protocols(alpn))
            .tls_cert_verification(false)
            .build()
            .unwrap();
        let url = format!("https://127.0.0.1:{origin}/");
        let mut fields = http::HeaderMap::new();
        let answer = http::HeaderValue::from_static("Basic YW5zd2VyOmdpdmVu");
        fields.insert("proxy-authorization", answer);
        for given in [None, Some(&fields), None, Some(&fields)] {
            let request = client.get(&url);
            let request = match given {
                Some(fields) => request.connect_headers(fields.clone()),
                None => request,
            };
            let body = request.send().await.unwrap().text().await.unwrap();
            assert_eq!(body, origin.to_string());
        }
        let route = Some("Basic cm91dGU6b3du".to_owned());
        let given = Some("Basic YW5zd2VyOmdpdmVu".to_owned());
        // Two tunnels, each reused by the later request with its fields.
        assert_eq!(*proxy.connects.lock().unwrap(), [route, given]);
    }
}

// VIPER-PATCH(connect-head-fields): a request's `CONNECT` order holds over
// HTTP/2 (names in lower case, RFC 9113 section 8.2.1) and HTTP/1.1, and is
// part of the tunnel's key. (A connection-specific field such as
// `Proxy-Connection` never goes on an HTTP/2 stream: wreq-proto's client
// strips it, RFC 9113 section 8.2.2.)
#[tokio::test]
async fn a_requests_connect_order_holds_and_keys_its_tunnel() {
    let http2 = (H2_AND_HTTP1, BOTH, ["user-agent", "x-order"]);
    let http1 = (HTTP1_ONLY, &[AlpnProtocol::HTTP1][..], ["User-Agent", "X-Order"]);
    for (select, alpn, written) in [http2, http1] {
        let origin = origin().await;
        let proxy = proxy(select, None).await;
        let config = wreq::Proxy::all(&proxy.url).unwrap().alpn_protocols(alpn);
        let client = Client::builder()
            .proxy(config)
            .tls_cert_verification(false)
            .build()
            .unwrap();
        let url = format!("https://127.0.0.1:{origin}/");
        let mut fields = http::HeaderMap::new();
        fields.insert("x-order", http::HeaderValue::from_static("second"));
        fields.insert("user-agent", http::HeaderValue::from_static("Agent/1"));
        let mut order = wreq::header::OrigHeaderMap::new();
        order.insert("User-Agent");
        order.insert("X-Order");
        let mut reversed = wreq::header::OrigHeaderMap::new();
        reversed.insert("X-Order");
        reversed.insert("User-Agent");
        for given in [Some(&order), None, Some(&order), Some(&reversed)] {
            let request = client.get(&url).connect_headers(fields.clone());
            let request = match given {
                Some(order) => request.connect_order(order.clone()),
                None => request,
            };
            let body = request.send().await.unwrap().text().await.unwrap();
            assert_eq!(body, origin.to_string());
        }
        // Three tunnels: the third request reuses the first's, and the
        // same names in another order open their own.
        // Over HTTP/1.1 the tunnel writes `Host` first, the order not
        // naming it.
        let host: &[&str] = if select == HTTP1_ONLY { &["Host"] } else { &[] };
        let lower = ["x-order", "user-agent"];
        let reversed = [written[1], written[0]];
        let expected = [
            [host, &written[..]].concat(),
            [host, &lower[..]].concat(),
            [host, &reversed[..]].concat(),
        ];
        assert_eq!(*proxy.names.lock().unwrap(), expected);
    }
}

// VIPER-PATCH(preconnect-connect-fields): a tunnel opened ahead with a
// request's `CONNECT` fields and order is keyed as that request's, so the
// request takes it (one `CONNECT` in all), over HTTP/2 and HTTP/1.1; a
// request without them opens its own.
#[tokio::test]
async fn a_preconnect_with_connect_fields_serves_the_request_with_them() {
    for (select, alpn) in [
        (H2_AND_HTTP1, BOTH),
        (HTTP1_ONLY, &[AlpnProtocol::HTTP1][..]),
    ] {
        let origin = origin().await;
        let proxy = proxy(select, None).await;
        let config = wreq::Proxy::all(&proxy.url).unwrap().alpn_protocols(alpn);
        let client = Client::builder()
            .proxy(config)
            .tls_cert_verification(false)
            .build()
            .unwrap();
        let url = format!("https://127.0.0.1:{origin}/");
        let mut fields = http::HeaderMap::new();
        fields.insert("user-agent", http::HeaderValue::from_static("Agent/1"));
        let mut order = wreq::header::OrigHeaderMap::new();
        order.insert("User-Agent");
        let uri: http::Uri = url.parse().unwrap();
        let opened = client
            .preconnect_with_connect_fields(uri, 1, None, fields.clone(), Some(order.clone()))
            .await;
        assert!(opened.iter().all(Result::is_ok), "{opened:?}");
        let request = client
            .get(&url)
            .connect_headers(fields)
            .connect_order(order);
        let body = request.send().await.unwrap().text().await.unwrap();
        assert_eq!(body, origin.to_string());
        assert_eq!(
            proxy.names.lock().unwrap().len(),
            1,
            "the preconnected tunnel served it"
        );
        let body = client.get(&url).send().await.unwrap().text().await.unwrap();
        assert_eq!(body, origin.to_string());
        assert_eq!(
            proxy.names.lock().unwrap().len(),
            2,
            "no fields, another key"
        );
    }
}

