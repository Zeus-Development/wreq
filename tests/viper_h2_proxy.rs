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

/// A loopback HTTPS proxy: its TCP connections and the ALPN lists offered.
struct Proxy {
    url: String,
    accepted: Arc<AtomicUsize>,
    offers: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn proxy(select: &'static [u8], refused: Option<(u16, Refusal)>) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let (accepted, offers) = (Arc::new(AtomicUsize::new(0)), Arc::default());
    let context = context(select, Arc::clone(&offers));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let tls = accept_tls(&context, stream).await;
            if tls.ssl().selected_alpn_protocol() == Some(b"h2".as_slice()) {
                let serve = service_fn(move |request| connect(request, refused));
                let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                tokio::spawn(conn.serve_connection(TokioIo::new(tls), serve));
            } else {
                tokio::spawn(connect_http1(tls));
            }
        }
    });
    Proxy {
        url,
        accepted,
        offers,
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
async fn connect_http1(mut tls: SslStream<TcpStream>) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tls.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap();
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
    let top: &(dyn std::error::Error + 'static) = error;
    let mut chain = std::iter::successors(Some(top), |&e| e.source());
    let found = chain.find_map(|e| e.downcast_ref::<ProxyFailure>());
    found.expect("a ProxyFailure in the chain").kind()
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
