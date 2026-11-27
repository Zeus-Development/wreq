//! VIPER-PATCH(proxy-hello-options): fork tests, with
//! VIPER-PATCH(trust-anchors). A loopback TLS listener records the
//! extensions of each ClientHello it gets and ends the handshake; it stands
//! for an origin (a direct `https` request) or an HTTPS proxy (the hello of
//! the proxy's own TLS connection). The hello to a proxy carries the same
//! per-connection options as an origin's, and the trust anchor IDs.

use std::sync::{Arc, Mutex};

use btls::ssl::{ExtensionType, SelectCertError, SslContext, SslMethod};
use tokio::net::TcpListener;
use wreq::{
    Client,
    tls::{AlpnProtocol, AlpsProtocol, KeyShare, TlsOptions},
};

/// The trust anchors extension (draft-ietf-tls-trust-anchor-ids).
const TRUST_ANCHORS: u16 = 0xca34;

/// What one hello carried: ECH GREASE, ALPS (new code point), the key
/// share groups and the trust anchors extension's body.
#[derive(Debug, Default, Clone, PartialEq)]
struct Hello {
    ech: bool,
    alps: bool,
    key_shares: Vec<u16>,
    trust_anchors: Option<Vec<u8>>,
}

/// The groups of a `key_share` extension's body (RFC 8446 section 4.2.8).
fn groups(body: &[u8]) -> Vec<u16> {
    let (mut groups, mut rest) = (Vec::new(), &body[2..]);
    while rest.len() >= 4 {
        groups.push(u16::from_be_bytes([rest[0], rest[1]]));
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        rest = &rest[4 + len..];
    }
    groups
}

/// A listener's address and the hellos it got.
async fn listener() -> (String, Arc<Mutex<Vec<Hello>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let hellos = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&hellos);
    let mut builder = SslContext::builder(SslMethod::tls()).unwrap();
    builder.set_select_certificate_callback(move |hello| {
        let ext = |kind: u16| hello.get_extension(ExtensionType::from(kind));
        seen.lock().unwrap().push(Hello {
            ech: ext(0xfe0d).is_some(),
            alps: ext(17613).is_some(),
            key_shares: ext(51).map(groups).unwrap_or_default(),
            trust_anchors: ext(TRUST_ANCHORS).map(<[u8]>::to_vec),
        });
        Err(SelectCertError::ERROR)
    });
    let context = builder.build();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let ssl = btls::ssl::Ssl::new(&context).unwrap();
            let mut tls = tokio_btls::SslStream::new(ssl, stream).unwrap();
            tokio::spawn(async move { drop(std::pin::Pin::new(&mut tls).accept().await) });
        }
    });
    (address, hellos)
}

fn options(trust_anchor_ids: Option<Vec<Vec<u8>>>) -> TlsOptions {
    let builder = TlsOptions::builder()
        .enable_ech_grease(true)
        .alps_protocols([AlpsProtocol::HTTP2])
        .alps_use_new_codepoint(true)
        .key_shares(vec![KeyShare::P256]);
    match trust_anchor_ids {
        Some(ids) => builder.trust_anchor_ids(ids).build(),
        None => builder.build(),
    }
}

/// The hello an origin gets from a client with `options`, and the hello an
/// HTTPS proxy offered `h2` gets from the same client.
async fn hellos(options: TlsOptions) -> (Hello, Hello) {
    let (origin, at_origin) = listener().await;
    let (proxy, at_proxy) = listener().await;
    let direct = Client::builder()
        .tls_options(options.clone())
        .build()
        .unwrap();
    direct
        .get(format!("https://{origin}/"))
        .send()
        .await
        .unwrap_err();
    let config = wreq::Proxy::all(format!("https://{proxy}"))
        .unwrap()
        .alpn_protocols(&[AlpnProtocol::HTTP2]);
    let proxied = Client::builder()
        .proxy(config)
        .tls_options(options)
        .build()
        .unwrap();
    proxied
        .get(format!("https://{origin}/"))
        .send()
        .await
        .unwrap_err();
    let origin = at_origin.lock().unwrap().clone();
    let proxy = at_proxy.lock().unwrap().clone();
    assert_eq!((origin.len(), proxy.len()), (1, 1));
    (origin[0].clone(), proxy[0].clone())
}

#[tokio::test]
async fn a_proxys_hello_carries_the_origins_options() {
    let (origin, proxy) = hellos(options(None)).await;
    let expected = Hello {
        ech: true,
        alps: true,
        key_shares: vec![23],
        trust_anchors: None,
    };
    assert_eq!(origin, expected);
    assert_eq!(proxy, expected);
}

#[tokio::test]
async fn without_options_neither_hello_carries_them() {
    let (origin, proxy) = hellos(TlsOptions::default()).await;
    for hello in [origin, proxy] {
        assert!(!hello.ech && !hello.alps && hello.trust_anchors.is_none());
    }
}

// VIPER-PATCH(trust-anchors): the IDs go on both hellos as the draft's
// list (a 16-bit length, then each ID with an 8-bit length).
#[tokio::test]
async fn both_hellos_request_the_trust_anchor_ids() {
    let ids = vec![vec![0x01, 0x02], vec![0x03]];
    let (origin, proxy) = hellos(options(Some(ids))).await;
    let wire = [0x00, 0x05, 0x02, 0x01, 0x02, 0x01, 0x03];
    assert_eq!(origin.trust_anchors.as_deref(), Some(&wire[..]));
    assert_eq!(proxy.trust_anchors.as_deref(), Some(&wire[..]));
}

#[tokio::test]
async fn an_empty_list_sends_the_extension_empty() {
    let (origin, proxy) = hellos(options(Some(Vec::new()))).await;
    assert_eq!(origin.trust_anchors.as_deref(), Some(&[0x00, 0x00][..]));
    assert_eq!(proxy.trust_anchors.as_deref(), Some(&[0x00, 0x00][..]));
}

#[tokio::test]
async fn an_empty_or_long_id_is_refused() {
    for id in [Vec::new(), vec![0; 256]] {
        let built = Client::builder()
            .tls_options(options(Some(vec![id])))
            .build();
        let failed = match built {
            Err(error) => error,
            Ok(client) => client.get("https://127.0.0.1:1/").send().await.unwrap_err(),
        };
        assert!(failed.is_builder(), "{failed:?}");
    }
}
