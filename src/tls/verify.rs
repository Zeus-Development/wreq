// VIPER-PATCH(verify-hook): a caller's certificate check, run after the
// handshake's own verification and before the connection is handed out,
// so before any request byte; and the verification result of a refused
// handshake, kept in a public typed error (RFC 5280 section 6, RFC 9525).
// VIPER-PATCH(async-verify-evidence): the check runs inside the handshake,
// as the TLS library's custom verification after the library's own chain
// and name verification, sees the stapled OCSP response (RFC 6066 section
// 8) and the signed certificate timestamps of the TLS extension (RFC 6962
// section 3.3), and may answer later: the handshake waits for it (the
// library's `ssl_verify_retry`) without blocking its thread.

//! A caller's check of the server's certificate chain, and the error of a
//! refused certificate.

// VIPER-PATCH(async-verify-evidence)
use std::{
    any::Any, // VIPER-PATCH(async-verify-evidence): fork review F1.
    error::Error as StdError,
    fmt,
    future::Future,
    os::raw::c_int,
    panic::{self, AssertUnwindSafe}, // VIPER-PATCH(async-verify-evidence)
    pin::Pin,
    ptr,
    slice, // VIPER-PATCH(async-verify-evidence)
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll, Waker},
};

use btls::{
    // VIPER-PATCH(async-verify-evidence)
    ssl::{SslAlert, SslRef, SslVerifyError, SslVerifyMode},
    x509::X509VerifyError,
};
// VIPER-PATCH(async-verify-evidence)
use btls_sys as ffi;
use foreign_types::ForeignTypeRef;
use tower::BoxError;

// VIPER-PATCH(async-verify-evidence): the check gets the handshake's
// evidence and answers through a future.
/// A caller's check of the server's certificate chain, run once per new TLS
// VIPER-PATCH(async-verify-evidence)
/// connection inside the handshake, after the handshake's own chain and
/// name verification succeeded, and before the connection carries any
/// request byte. On a resumed connection, where the handshake verifies
/// nothing again, it runs on the session's chain once the handshake ends,
/// still before any request byte.
pub trait CertVerifyHook: Send + Sync {
    /// Checks `chain` (DER, the server's certificate first, as the server
    // VIPER-PATCH(async-verify-evidence)
    /// sent it) for `server_name` (the host the connection was made for),
    /// with what else the handshake delivered for it (`evidence`). The
    /// handshake waits for the returned future without blocking its thread.
    /// An error refuses the certificate: the handshake ends with an alert
    /// (after it, on a resumed connection), the connection is closed and
    /// the request fails with a [`CertificateRefused`] holding this error.
    fn verify(
        &self,
        chain: &[&[u8]],
        server_name: &str,
        // VIPER-PATCH(async-verify-evidence)
        evidence: &HandshakeEvidence<'_>,
    ) -> CertVerifyFuture;
}

/// A shared [`CertVerifyHook`].
pub type CertVerifyHookRef = Arc<dyn CertVerifyHook>;

// VIPER-PATCH(async-verify-evidence): the hook's answer, and the evidence.
/// A [`CertVerifyHook`]'s answer: `Ok` accepts the certificate.
pub type CertVerifyFuture = Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send>>;

/// What the handshake delivered for the server's certificate besides its
/// chain, as received; each is present only when the client asked for it
/// and the server sent it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct HandshakeEvidence<'a> {
    /// The stapled OCSP response (RFC 6066 section 8; in TLS 1.3 the
    // VIPER-PATCH(async-verify-evidence)
    /// `status_request` extension of the leaf's `CertificateEntry`, RFC 8446
    /// section 4.4.2).
    pub ocsp_response: Option<&'a [u8]>,
    /// The `signed_certificate_timestamp` extension's body (RFC 6962
    /// section 3.3): a `SignedCertificateTimestampList`, each SCT behind its
    /// two-byte length, as the library checked its syntax.
    pub sct_list: Option<&'a [u8]>,
}

impl<'a> HandshakeEvidence<'a> {
    fn of(ssl: &'a SslRef) -> Self {
        Self {
            ocsp_response: ssl.ocsp_status(),
            sct_list: sct_list(ssl),
        }
    }
}

/// The SCT list `ssl`'s session holds, if any.
#[allow(unsafe_code)]
fn sct_list(ssl: &SslRef) -> Option<&[u8]> {
    let (mut data, mut len) = (ptr::null(), 0);
    // SAFETY: `ssl` is a live connection; the library points `data` at
    // `len` bytes its session owns, which outlive the borrow of `ssl`.
    unsafe { ffi::SSL_get0_signed_cert_timestamp_list(ssl.as_ptr(), &mut data, &mut len) };
    // SAFETY: as above; `data` is non-null and `len` bytes long.
    (len != 0 && !data.is_null()).then(|| unsafe { slice::from_raw_parts(data, len) })
}

/// A server certificate that was refused before any request byte: by the
/// handshake's own verification ([`Self::verify_error`] says why) or by the
/// caller's [`CertVerifyHook`] (its error is the source).
#[derive(Debug)]
pub struct CertificateRefused {
    verify_error: Option<X509VerifyError>,
    source: BoxError,
}

impl CertificateRefused {
    /// The TLS library's verification result, when the handshake's own
    /// verification refused the certificate; `None` when the hook did.
    pub fn verify_error(&self) -> Option<X509VerifyError> {
        self.verify_error
    }

    // VIPER-PATCH(async-verify-evidence): a refusal `verification` recorded.
    /// The handshake error `source`, wrapped when the handshake's own
    /// verification failed on `ssl`; any other failure stays as it is. A
    /// handshake that failed before verifying reports `INVALID_CALL`. With
    /// verification off the library still verifies and keeps the result,
    // VIPER-PATCH(async-verify-evidence)
    /// which then never ends the handshake, so a failure is unchanged. With
    /// a hook, `verification` holds what refused the certificate.
    pub(crate) fn from_handshake(
        ssl: &SslRef,
        verification: Option<&Verification>,
        source: BoxError,
    ) -> BoxError {
        if let Some(verification) = verification {
            return match verification.take_refusal() {
                Some(Refusal::Library(verify_error)) => Box::new(Self {
                    verify_error,
                    source,
                }),
                Some(Refusal::Hook(source)) => Self::hook(source),
                // VIPER-PATCH(async-verify-evidence): fork review F2.
                Some(Refusal::Internal) | None => source,
            };
        }
        if !ssl.verify_mode().contains(SslVerifyMode::PEER) {
            return source;
        }
        match ssl.verify_result() {
            Err(verify_error) if verify_error != X509VerifyError::INVALID_CALL => Box::new(Self {
                verify_error: Some(verify_error),
                source,
            }),
            Ok(()) | Err(_) => source,
        }
    }

    // VIPER-PATCH(async-verify-evidence): the hook's refusal.
    fn hook(source: BoxError) -> BoxError {
        Box::new(Self {
            verify_error: None,
            source,
        })
    }
}

impl fmt::Display for CertificateRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the server's certificate was refused")
    }
}

impl StdError for CertificateRefused {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.source)
    }
}

// VIPER-PATCH(async-verify-evidence): one handshake's run of the hook, as
// the library's custom verification.
/// What refused a certificate during the handshake.
enum Refusal {
    /// The library's own verification, with its result.
    Library(Option<X509VerifyError>),
    /// The hook, with its error.
    Hook(BoxError),
    // VIPER-PATCH(async-verify-evidence): fork review F1 and F2.
    /// The check could not run: the library's verification could not be
    /// set up, the chain could not be encoded or the hook panicked. Fatal
    /// whatever the verify mode, as a setup failure is in the library.
    Internal,
}

/// Why the library's own verification failed.
enum LibraryFailure {
    /// It could not be set up; the library then fails the handshake
    /// whatever the verify mode.
    Setup,
    /// The chain did not verify: the result, and the alert the library
    /// sends.
    Verify(Option<X509VerifyError>, SslAlert),
}

#[derive(Default)]
struct State {
    /// The waker of the task driving the handshake.
    waker: Option<Waker>,
    /// The hook's answer while it is pending.
    running: Option<CertVerifyFuture>,
    refused: Option<Refusal>,
    /// Whether the handshake verified the chain (a resumed one does not).
    ran: bool,
    // VIPER-PATCH(async-verify-evidence): fork review F1.
    /// A panic of the hook, caught in the library's callback (it cannot
    /// unwind through the library), to resume in the connecting task.
    panic: Option<Box<dyn Any + Send>>,
}

/// One handshake's run of a [`CertVerifyHook`], shared by the library's
/// custom verification callback and the connector driving the handshake.
pub(crate) struct Verification {
    hook: CertVerifyHookRef,
    host: String,
    state: Mutex<State>,
}

impl Verification {
    /// Installs `hook` on `ssl` as the library's custom verification, for
    /// `host`, keeping `ssl`'s verify mode.
    pub(crate) fn install(hook: &CertVerifyHookRef, ssl: &mut SslRef, host: &str) -> Arc<Self> {
        let this = Arc::new(Self {
            hook: Arc::clone(hook),
            host: host.to_owned(),
            state: Mutex::default(),
        });
        let callback = Arc::clone(&this);
        let mode = ssl.verify_mode();
        ssl.set_custom_verify_callback(mode, move |ssl| callback.step(ssl));
        this
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wakes `waker`'s task when a pending answer is ready.
    pub(crate) fn set_waker(&self, waker: &Waker) {
        match &mut self.state().waker {
            Some(current) => current.clone_from(waker),
            slot => *slot = Some(waker.clone()),
        }
    }

    fn take_refusal(&self) -> Option<Refusal> {
        self.state().refused.take()
    }

    /// One call of the custom verification: the library's own
    /// verification, then the hook; `Retry` while its answer is pending.
    /// With verification off the library's failure does not end the
    /// handshake (as without a hook), and the library ignores any failure.
    // VIPER-PATCH(async-verify-evidence): fork review F1 and F2: every
    // failure is recorded, and a panic is caught.
    fn step(&self, ssl: &mut SslRef) -> Result<(), SslVerifyError> {
        let mut state = self.state();
        // VIPER-PATCH(async-verify-evidence)
        let stepped = panic::catch_unwind(AssertUnwindSafe(|| self.advance(&mut state, ssl)));
        let refusal = match stepped {
            Ok(Ok(Poll::Pending)) => return Err(SslVerifyError::Retry),
            Ok(Ok(Poll::Ready(()))) => return Ok(()),
            Ok(Err((refusal, alert))) => (refusal, alert),
            Err(payload) => {
                state.running = None;
                state.panic = Some(payload);
                (Refusal::Internal, SslAlert::INTERNAL_ERROR)
            }
        };
        state.refused = Some(refusal.0);
        Err(SslVerifyError::Invalid(refusal.1))
    }

    /// The custom verification's work: the library's own verification on
    /// the first call, then the hook's answer, `Pending` while it is.
    fn advance(
        &self,
        state: &mut State,
        ssl: &mut SslRef,
    ) -> Result<Poll<()>, (Refusal, SslAlert)> {
        let internal = (Refusal::Internal, SslAlert::INTERNAL_ERROR);
        if state.running.is_none() {
            state.ran = true;
            // VIPER-PATCH(async-verify-evidence)
            match library_verify(ssl) {
                Err(LibraryFailure::Setup) => return Err(internal),
                Err(LibraryFailure::Verify(verify_error, alert))
                    if ssl.verify_mode().contains(SslVerifyMode::PEER) =>
                {
                    return Err((Refusal::Library(verify_error), alert));
                }
                Ok(()) | Err(LibraryFailure::Verify(..)) => {}
            }
            let Ok(chain) = der_chain(ssl) else {
                // VIPER-PATCH(async-verify-evidence)
                return Err(internal);
            };
            let chain: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
            let evidence = HandshakeEvidence::of(ssl);
            state.running = Some(self.hook.verify(&chain, &self.host, &evidence));
        }
        let waker = state.waker.clone().unwrap_or_else(|| Waker::noop().clone());
        let Some(running) = state.running.as_mut() else {
            // VIPER-PATCH(async-verify-evidence)
            return Err(internal);
        };
        let answer = match running.as_mut().poll(&mut Context::from_waker(&waker)) {
            // VIPER-PATCH(async-verify-evidence)
            Poll::Pending => return Ok(Poll::Pending),
            Poll::Ready(answer) => answer,
        };
        state.running = None;
        match answer {
            Ok(()) => Ok(Poll::Ready(())),
            Err(source) => Err((Refusal::Hook(source), SslAlert::CERTIFICATE_UNKNOWN)),
        }
    }

    // VIPER-PATCH(async-verify-evidence): fork review F1.
    /// Resumes, in the task driving the handshake, a panic of the hook that
    /// the library's callback caught.
    pub(crate) fn resume_panic(&self) {
        if let Some(payload) = self.state().panic.take() {
            panic::resume_unwind(payload);
        }
    }

    /// After a successful handshake on `ssl`: the hook's refusal, which the
    /// library ignored with verification off; or, on a resumed connection,
    /// the hook's check of the session's chain, to wait for.
    pub(crate) fn after_handshake(
        &self,
        ssl: &SslRef,
    ) -> Result<Option<CertVerifyFuture>, BoxError> {
        let mut state = self.state();
        // VIPER-PATCH(async-verify-evidence): fork review F2: an internal
        // failure stays fatal with verification off.
        match state.refused.take() {
            Some(Refusal::Hook(source)) => return Err(CertificateRefused::hook(source)),
            Some(Refusal::Internal) => {
                return Err("the server's certificate could not be checked".into());
            }
            Some(Refusal::Library(_)) | None => {}
        }
        if state.ran {
            return Ok(None);
        }
        let der = der_chain(ssl)?;
        let chain: Vec<&[u8]> = der.iter().map(Vec::as_slice).collect();
        let evidence = HandshakeEvidence::of(ssl);
        let check = self.hook.verify(&chain, &self.host, &evidence);
        Ok(Some(Box::pin(async move {
            check.await.map_err(CertificateRefused::hook)
        })))
    }
}

/// `ssl`'s peer chain in DER, the server's certificate first.
fn der_chain(ssl: &SslRef) -> Result<Vec<Vec<u8>>, BoxError> {
    let der = ssl
        .peer_cert_chain()
        .into_iter()
        .flatten()
        .map(|cert| cert.to_der())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(der)
}

/// The library's own verification of `ssl`'s peer chain, as it runs it
/// when no custom verification is set (BoringSSL's
/// `ssl_crypto_x509_session_verify_cert_chain`, client side): the context's
/// trust store (the connector sets no separate verify store), the
/// `ssl_server` defaults, the connection's verification parameters (its
/// host among them) and, after a refused ECH offer, the public name. On
// VIPER-PATCH(async-verify-evidence)
/// failure, whether it could not be set up, or the verification result and
/// the alert the library sends.
#[allow(unsafe_code)]
// VIPER-PATCH(async-verify-evidence): fork review F2: a setup failure is
// told apart from a verification result.
fn library_verify(ssl: &SslRef) -> Result<(), LibraryFailure> {
    struct StoreContext(*mut ffi::X509_STORE_CTX);
    impl Drop for StoreContext {
        fn drop(&mut self) {
            // SAFETY: the context was allocated by `X509_STORE_CTX_new`.
            unsafe { ffi::X509_STORE_CTX_free(self.0) }
        }
    }
    // VIPER-PATCH(async-verify-evidence)
    let Some(chain) = ssl.peer_cert_chain() else {
        // VIPER-PATCH(async-verify-evidence)
        return Err(LibraryFailure::Setup);
    };
    let Some(leaf) = chain.get(0) else {
        // VIPER-PATCH(async-verify-evidence)
        return Err(LibraryFailure::Setup);
    };
    // SAFETY: `ssl`, its context, `chain` and `leaf` are live for this call;
    // the store context is initialized before use and freed by `StoreContext`.
    unsafe {
        let ctx = ffi::X509_STORE_CTX_new();
        if ctx.is_null() {
            // VIPER-PATCH(async-verify-evidence)
            return Err(LibraryFailure::Setup);
        }
        let ctx = StoreContext(ctx);
        let raw = ssl.as_ptr();
        let store = ffi::SSL_CTX_get_cert_store(ffi::SSL_get_SSL_CTX(raw));
        let (mut name, mut name_len) = (ptr::null(), 0);
        ffi::SSL_get0_ech_name_override(raw, &mut name, &mut name_len);
        let param = || ffi::X509_STORE_CTX_get0_param(ctx.0);
        let index = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ready = ffi::X509_STORE_CTX_init(ctx.0, store, leaf.as_ptr(), chain.as_ptr()) != 0
            && ffi::X509_STORE_CTX_set_ex_data(ctx.0, index, raw.cast()) != 0
            && ffi::X509_STORE_CTX_set_default(ctx.0, c"ssl_server".as_ptr()) != 0
            && ffi::X509_VERIFY_PARAM_set1(param(), ffi::SSL_get0_param(raw)) != 0
            && (name_len == 0 || ffi::X509_VERIFY_PARAM_set1_host(param(), name, name_len) != 0);
        if !ready {
            // VIPER-PATCH(async-verify-evidence)
            return Err(LibraryFailure::Setup);
        }
        let verified = ffi::X509_verify_cert(ctx.0) > 0;
        // As the library: a failure with verification off is not fatal.
        if verified || !ssl.verify_mode().contains(SslVerifyMode::PEER) {
            ffi::ERR_clear_error();
        }
        if verified {
            return Ok(());
        }
        let result = ffi::X509_STORE_CTX_get_error(ctx.0);
        let alert = alert(ffi::SSL_alert_from_verify_result(result.into()));
        // VIPER-PATCH(async-verify-evidence)
        Err(LibraryFailure::Verify(
            X509VerifyError::from_raw(result).err(),
            alert,
        ))
    }
}

/// The alert `SSL_alert_from_verify_result` names.
fn alert(raw: c_int) -> SslAlert {
    match raw {
        ffi::SSL_AD_UNKNOWN_CA => SslAlert::UNKNOWN_CA,
        ffi::SSL_AD_BAD_CERTIFICATE => SslAlert::BAD_CERTIFICATE,
        ffi::SSL_AD_DECRYPT_ERROR => SslAlert::DECRYPT_ERROR,
        ffi::SSL_AD_CERTIFICATE_EXPIRED => SslAlert::CERTIFICATE_EXPIRED,
        ffi::SSL_AD_CERTIFICATE_REVOKED => SslAlert::CERTIFICATE_REVOKED,
        ffi::SSL_AD_INTERNAL_ERROR => SslAlert::INTERNAL_ERROR,
        ffi::SSL_AD_HANDSHAKE_FAILURE => SslAlert::HANDSHAKE_FAILURE,
        ffi::SSL_AD_UNSUPPORTED_CERTIFICATE => SslAlert::UNSUPPORTED_CERTIFICATE,
        _ => SslAlert::CERTIFICATE_UNKNOWN,
    }
}
