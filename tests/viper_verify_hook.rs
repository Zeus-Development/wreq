//! VIPER-PATCH(verify-hook): fork tests. A loopback TLS origin counts the
//! bytes it receives after its handshake; the caller's hook sees the chain
//! and the host, and a refusal, by the hook or by the handshake's own
//! verification, is a `CertificateRefused` before any request byte.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use btls::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion},
    x509::{
        X509, X509Builder, X509NameBuilder, X509VerifyError,
        extension::{BasicConstraints, SubjectAlternativeName},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};
use tokio_btls::SslStream;
use wreq::{
    Client,
    tls::{
        trust::CertStore,
        verify::{CertVerifyHook, CertificateRefused},
    },
};

const DAY: i64 = 86_400;

fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

/// A certificate for `key` signed by `signer` (a CA when `ip` is `None`),
/// valid from `from` to `to` days from now.
fn certificate(
    key: &PKey<Private>,
    signer: Option<(&X509, &PKey<Private>)>,
    ip: Option<&str>,
    (from, to): (i64, i64),
) -> X509 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = rand_serial();
    let number = BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&number).unwrap();
    // Each CA has its own name, so another CA's certificate has no issuer.
    let common_name = ip.map_or_else(|| format!("ca {serial}"), |_| "origin".to_owned());
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, &common_name)
        .unwrap();
    let name = name.build();
    builder.set_subject_name(&name).unwrap();
    builder
        .set_issuer_name(signer.map_or(&*name, |(ca, _)| ca.subject_name()))
        .unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(now + from * DAY).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(now + to * DAY).unwrap())
        .unwrap();
    match ip {
        None => {
            let ca = BasicConstraints::new().critical().ca().build().unwrap();
            builder.append_extension(&ca).unwrap();
        }
        Some(ip) => {
            let context = builder.x509v3_context(signer.map(|(ca, _)| &**ca), None);
            let san = SubjectAlternativeName::new()
                .ip(ip)
                .build(&context)
                .unwrap();
            builder.append_extension(&san).unwrap();
        }
    }
    builder
        .sign(signer.map_or(key, |(_, k)| k), MessageDigest::sha256())
        .unwrap();
    builder.build()
}

fn rand_serial() -> u32 {
    let mut bytes = [0_u8; 4];
    btls::rand::rand_bytes(&mut bytes).unwrap();
    u32::from_le_bytes(bytes) >> 1
}

/// A CA and an origin certificate for 127.0.0.1 valid over `days`.
struct Pki {
    ca: X509,
    leaf: X509,
    leaf_key: PKey<Private>,
}

fn pki(days: (i64, i64)) -> Pki {
    let ca_key = key();
    let ca = certificate(&ca_key, None, None, (-1, 30));
    let leaf_key = key();
    let leaf = certificate(&leaf_key, Some((&ca, &ca_key)), Some("127.0.0.1"), days);
    Pki { ca, leaf, leaf_key }
}

/// An origin on a loopback port serving one TLS connection with `pki`'s
/// leaf; it answers a request head with 200, and reports the bytes it
/// received after its handshake (`None` when the handshake failed).
async fn origin(pki: &Pki) -> (String, oneshot::Receiver<Option<usize>>) {
    origin_with(pki, |_| {}).await
}

/// [`origin`], with `configure` applied to its TLS context.
async fn origin_with(
    pki: &Pki,
    configure: impl FnOnce(&mut SslContextBuilder),
) -> (String, oneshot::Receiver<Option<usize>>) {
    let mut context = SslContext::builder(SslMethod::tls()).unwrap();
    context.set_private_key(&pki.leaf_key).unwrap();
    context.set_certificate(&pki.leaf).unwrap();
    configure(&mut context);
    let context = context.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, received) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ssl = Ssl::new(&context).unwrap();
        let mut tls = SslStream::new(ssl, stream).unwrap();
        if Pin::new(&mut tls).accept().await.is_err() {
            sender.send(None).ok();
            return;
        }
        let (mut head, mut buffer) = (Vec::new(), [0_u8; 1024]);
        while let Ok(read @ 1..) = tls.read(&mut buffer).await {
            head.extend_from_slice(&buffer[..read]);
            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                let response = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
                tls.write_all(response).await.ok();
                break;
            }
        }
        sender.send(Some(head.len())).ok();
    });
    (format!("https://127.0.0.1:{port}/"), received)
}

/// What the hook was called with, and whether it refuses.
#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<(usize, String)>>,
    refuse: bool,
}

impl CertVerifyHook for Recorder {
    fn verify(
        &self,
        chain: &[&[u8]],
        server_name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let leaf = X509::from_der(chain[0]).unwrap();
        assert!(leaf.subject_alt_names().is_some());
        self.calls
            .lock()
            .unwrap()
            .push((chain.len(), server_name.to_owned()));
        if self.refuse {
            Err("refused by the hook".into())
        } else {
            Ok(())
        }
    }
}

fn client(pki: &Pki, hook: &Arc<Recorder>) -> Client {
    let store = CertStore::builder()
        .add_der_cert(&pki.ca.to_der().unwrap())
        .build()
        .unwrap();
    Client::builder()
        .tls_cert_store(store)
        .tls_verify_hook(Arc::clone(hook) as _)
        .no_proxy()
        .build()
        .unwrap()
}

fn refusal(error: &wreq::Error) -> &CertificateRefused {
    let top: &(dyn std::error::Error + 'static) = error;
    let mut chain = std::iter::successors(Some(top), |&e| e.source());
    let found = chain.find_map(|e| e.downcast_ref::<CertificateRefused>());
    found.unwrap_or_else(|| panic!("no CertificateRefused in {error:?}"))
}

#[tokio::test]
async fn an_accepting_hook_sees_the_chain_and_the_host() {
    let (pki, hook) = (pki((-1, 30)), Arc::new(Recorder::default()));
    let (url, received) = origin(&pki).await;
    let response = client(&pki, &hook).get(&url).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(*hook.calls.lock().unwrap(), [(1, "127.0.0.1".to_owned())]);
    assert!(received.await.unwrap().unwrap() > 0);
}

#[tokio::test]
async fn a_refusing_hook_fails_before_any_request_byte() {
    let pki = pki((-1, 30));
    let hook = Arc::new(Recorder {
        refuse: true,
        ..Recorder::default()
    });
    let (url, received) = origin(&pki).await;
    let error = client(&pki, &hook).get(&url).send().await.unwrap_err();
    let refused = refusal(&error);
    assert_eq!(refused.verify_error(), None);
    let source = std::error::Error::source(refused).unwrap();
    assert_eq!(source.to_string(), "refused by the hook");
    assert_eq!(hook.calls.lock().unwrap().len(), 1);
    assert_eq!(received.await.unwrap(), Some(0));
}

#[tokio::test]
async fn the_handshakes_own_refusal_keeps_its_verify_result() {
    let cases = [
        ((-30, -1), X509VerifyError::CERT_HAS_EXPIRED),
        ((1, 30), X509VerifyError::CERT_NOT_YET_VALID),
    ];
    for (days, expected) in cases {
        let (pki, hook) = (pki(days), Arc::new(Recorder::default()));
        let (url, received) = origin(&pki).await;
        let error = client(&pki, &hook).get(&url).send().await.unwrap_err();
        assert_eq!(refusal(&error).verify_error(), Some(expected));
        assert!(hook.calls.lock().unwrap().is_empty());
        assert_eq!(received.await.unwrap(), None);
    }
    let (pki, other) = (pki((-1, 30)), pki((-1, 30)));
    let hook = Arc::new(Recorder::default());
    let (url, _) = origin(&pki).await;
    let error = client(&other, &hook).get(&url).send().await.unwrap_err();
    let unknown = X509VerifyError::UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    assert_eq!(refusal(&error).verify_error(), Some(unknown));
}

/// With verification off the library still verifies and keeps the result;
/// a handshake that then fails for another reason (a TLS 1.2 origin that
/// demands a client certificate the client does not have) is not a refused
/// certificate.
#[tokio::test]
async fn with_verification_off_another_failure_is_not_a_refused_certificate() {
    let (pki, other) = (pki((-1, 30)), pki((-1, 30)));
    let (url, received) = origin_with(&pki, |context| {
        context
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        context.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    })
    .await;
    let store = CertStore::builder()
        .add_der_cert(&other.ca.to_der().unwrap())
        .build()
        .unwrap();
    let client = Client::builder()
        .tls_cert_store(store)
        .tls_cert_verification(false)
        .no_proxy()
        .build()
        .unwrap();
    let error = client.get(&url).send().await.unwrap_err();
    let top: &(dyn std::error::Error + 'static) = &error;
    let mut chain = std::iter::successors(Some(top), |&e| e.source());
    assert!(!chain.any(|e| e.is::<CertificateRefused>()), "{error:?}");
    assert_eq!(received.await.unwrap(), None);
}
