//! VIPER-PATCH(verify-hook): fork tests. A loopback TLS origin counts the
//! bytes it receives after its handshake; the caller's hook sees the chain
//! and the host, and a refusal, by the hook or by the handshake's own
//! verification, is a `CertificateRefused` before any request byte.
//! VIPER-PATCH(async-verify-evidence): the hook sees the stapled OCSP
//! response and the SCT list, may answer later without blocking the
//! thread, and refuses inside the handshake.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    // VIPER-PATCH(async-verify-evidence)
    time::{Duration, SystemTime, UNIX_EPOCH},
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
    ClientBuilder, // VIPER-PATCH(async-verify-evidence)
    tls::{
        // VIPER-PATCH(async-verify-evidence)
        TlsOptions,
        trust::CertStore,
        // VIPER-PATCH(async-verify-evidence): the hook's answer and evidence.
        verify::{CertVerifyFuture, CertVerifyHook, CertificateRefused, HandshakeEvidence},
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

// VIPER-PATCH(async-verify-evidence): the hook answers through a future.
impl CertVerifyHook for Recorder {
    fn verify(
        &self,
        chain: &[&[u8]],
        server_name: &str,
        // VIPER-PATCH(async-verify-evidence)
        _: &HandshakeEvidence<'_>,
    ) -> CertVerifyFuture {
        let leaf = X509::from_der(chain[0]).unwrap();
        assert!(leaf.subject_alt_names().is_some());
        self.calls
            .lock()
            .unwrap()
            .push((chain.len(), server_name.to_owned()));
        // VIPER-PATCH(async-verify-evidence)
        let answer = if self.refuse {
            Err("refused by the hook".into())
        } else {
            Ok(())
            // VIPER-PATCH(async-verify-evidence)
        };
        Box::pin(std::future::ready(answer))
    }
}

fn client(pki: &Pki, hook: &Arc<Recorder>) -> Client {
    builder(pki, Arc::clone(hook) as _).build().unwrap()
}

// VIPER-PATCH(async-verify-evidence): a client builder trusting `pki`'s CA.
fn builder(pki: &Pki, hook: Arc<dyn CertVerifyHook>) -> ClientBuilder {
    let store = CertStore::builder()
        .add_der_cert(&pki.ca.to_der().unwrap())
        .build()
        .unwrap();
    Client::builder()
        .tls_cert_store(store)
        // VIPER-PATCH(async-verify-evidence)
        .tls_verify_hook(hook)
        .no_proxy()
    // VIPER-PATCH(async-verify-evidence)
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
    // VIPER-PATCH(async-verify-evidence): the refusal ends the handshake.
    assert_eq!(received.await.unwrap(), None);
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

// VIPER-PATCH(async-verify-evidence): the tests of the evidence and of an
// answer that comes later.

const OCSP: &[u8] = b"an OCSP response";
/// A `SignedCertificateTimestampList` of two SCTs (RFC 6962 section 3.3).
const SCT_LIST: &[u8] = &[0, 9, 0, 3, 1, 2, 3, 0, 2, 4, 5];

/// Makes `context` staple [`OCSP`] and send [`SCT_LIST`] to a client that
/// asks for them.
#[allow(unsafe_code)]
fn staple(context: &mut SslContextBuilder) {
    // SAFETY: a live context; the library copies both buffers.
    unsafe {
        let ctx = context.as_ptr();
        assert_eq!(
            btls_sys::SSL_CTX_set_ocsp_response(ctx, OCSP.as_ptr(), OCSP.len()),
            1
        );
        let list = btls_sys::SSL_CTX_set_signed_cert_timestamp_list(
            ctx,
            SCT_LIST.as_ptr(),
            SCT_LIST.len(),
        );
        assert_eq!(list, 1);
    }
}

type Evidence = (Option<Vec<u8>>, Option<Vec<u8>>);

/// A hook that records the evidence and answers from another thread after
/// `delay`, refusing when `refuse`.
struct Later {
    delay: Duration,
    refuse: bool,
    evidence: Mutex<Vec<Evidence>>,
}

impl Later {
    fn new(delay: Duration, refuse: bool) -> Arc<Self> {
        let evidence = Mutex::default();
        Arc::new(Self {
            delay,
            refuse,
            evidence,
        })
    }
}

impl CertVerifyHook for Later {
    fn verify(&self, _: &[&[u8]], _: &str, evidence: &HandshakeEvidence<'_>) -> CertVerifyFuture {
        let seen = (
            evidence.ocsp_response.map(<[u8]>::to_vec),
            evidence.sct_list.map(<[u8]>::to_vec),
        );
        self.evidence.lock().unwrap().push(seen);
        let (sender, answer) = oneshot::channel();
        let (delay, refuse) = (self.delay, self.refuse);
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            sender
                .send(if refuse { Err("refused later") } else { Ok(()) })
                .ok();
        });
        Box::pin(async move { Ok(answer.await??) })
    }
}

fn asking() -> TlsOptions {
    TlsOptions::builder()
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .build()
}

#[tokio::test]
async fn the_hook_sees_the_stapled_ocsp_response_and_the_sct_list() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let (pki, hook) = (pki((-1, 30)), Later::new(Duration::ZERO, false));
        let (url, _) = origin_with(&pki, |context| {
            context.set_max_proto_version(Some(version)).unwrap();
            staple(context);
        })
        .await;
        let client = builder(&pki, Arc::clone(&hook) as _)
            .tls_options(asking())
            .build()
            .unwrap();
        assert_eq!(client.get(&url).send().await.unwrap().status(), 200);
        let expected = (Some(OCSP.to_vec()), Some(SCT_LIST.to_vec()));
        assert_eq!(*hook.evidence.lock().unwrap(), [expected], "{version:?}");
    }
    let (pki, hook) = (pki((-1, 30)), Later::new(Duration::ZERO, false));
    let (url, _) = origin_with(&pki, staple).await;
    let client = builder(&pki, Arc::clone(&hook) as _).build().unwrap();
    assert_eq!(client.get(&url).send().await.unwrap().status(), 200);
    assert_eq!(*hook.evidence.lock().unwrap(), [(None, None)]);
}

/// On one thread, a handshake waiting for a later answer lets another
/// client's request complete meanwhile.
#[tokio::test]
async fn a_pending_answer_does_not_block_the_thread() {
    let (slow_pki, fast_pki) = (pki((-1, 30)), pki((-1, 30)));
    let slow_hook = Later::new(Duration::from_millis(200), false);
    let (slow_url, slow_received) = origin(&slow_pki).await;
    let slow = builder(&slow_pki, slow_hook as _).build().unwrap();
    let slow = tokio::spawn(async move { slow.get(&slow_url).send().await.unwrap().status() });
    let fast_hook = Arc::new(Recorder::default());
    let (fast_url, _) = origin(&fast_pki).await;
    let fast = client(&fast_pki, &fast_hook)
        .get(&fast_url)
        .send()
        .await
        .unwrap();
    assert_eq!(fast.status(), 200);
    assert!(!slow.is_finished());
    assert_eq!(slow.await.unwrap(), 200);
    assert!(slow_received.await.unwrap().unwrap() > 0);
}

#[tokio::test]
async fn a_late_refusal_sends_no_request_byte() {
    let (pki, hook) = (pki((-1, 30)), Later::new(Duration::from_millis(100), true));
    let (url, received) = origin(&pki).await;
    let client = builder(&pki, hook as _).build().unwrap();
    let error = client.get(&url).send().await.unwrap_err();
    let refused = refusal(&error);
    assert_eq!(refused.verify_error(), None);
    let source = std::error::Error::source(refused).unwrap();
    assert_eq!(source.to_string(), "refused later");
    assert_eq!(received.await.unwrap(), None);
}

/// With verification off the library ignores a failed custom verification,
/// so the hook's refusal ends the connection after the handshake, still
/// before any request byte.
#[tokio::test]
async fn with_verification_off_the_hooks_refusal_still_refuses() {
    let pki = pki((-1, 30));
    let hook = Arc::new(Recorder {
        refuse: true,
        ..Recorder::default()
    });
    let (url, received) = origin(&pki).await;
    let client = builder(&pki, Arc::clone(&hook) as _)
        .tls_cert_verification(false)
        .build()
        .unwrap();
    let error = client.get(&url).send().await.unwrap_err();
    assert_eq!(refusal(&error).verify_error(), None);
    assert_eq!(hook.calls.lock().unwrap().len(), 1);
    assert_eq!(received.await.unwrap(), Some(0));
}

/// An origin serving `count` TLS connections, one response each, reporting
/// whether each handshake resumed a session.
async fn resuming_origin(pki: &Pki, count: usize) -> (String, tokio::sync::mpsc::Receiver<bool>) {
    let mut context = SslContext::builder(SslMethod::tls()).unwrap();
    context.set_private_key(&pki.leaf_key).unwrap();
    context.set_certificate(&pki.leaf).unwrap();
    let context = context.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, resumed) = tokio::sync::mpsc::channel(count);
    tokio::spawn(async move {
        for _ in 0..count {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = SslStream::new(Ssl::new(&context).unwrap(), stream).unwrap();
            Pin::new(&mut tls).accept().await.unwrap();
            sender.send(tls.ssl().session_reused()).await.unwrap();
            let (mut head, mut buffer) = (Vec::new(), [0_u8; 1024]);
            while !head.ends_with(b"\r\n\r\n") {
                let read = tls.read(&mut buffer).await.unwrap();
                assert!(read > 0, "the request head ended early");
                head.extend_from_slice(&buffer[..read]);
            }
            let response = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            tls.write_all(response).await.unwrap();
            tls.shutdown().await.ok();
        }
    });
    (format!("https://127.0.0.1:{port}/"), resumed)
}

/// A resumed handshake verifies nothing again, so the hook checks the
/// session's chain after it.
#[tokio::test]
async fn a_resumed_connection_is_checked_after_its_handshake() {
    let (pki, hook) = (pki((-1, 30)), Arc::new(Recorder::default()));
    let (url, mut resumed) = resuming_origin(&pki, 2).await;
    let options = TlsOptions::builder()
        .pre_shared_key(true)
        .session_ticket(true)
        .build();
    let client = builder(&pki, Arc::clone(&hook) as _)
        .tls_options(options)
        .build()
        .unwrap();
    for expected in [false, true] {
        assert_eq!(client.get(&url).send().await.unwrap().status(), 200);
        assert_eq!(resumed.recv().await, Some(expected));
    }
    assert_eq!(hook.calls.lock().unwrap().len(), 2);
}
