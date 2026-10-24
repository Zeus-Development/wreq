// VIPER-PATCH(verify-hook): a caller's certificate check, run after the
// handshake's own verification and before the connection is handed out,
// so before any request byte; and the verification result of a refused
// handshake, kept in a public typed error (RFC 5280 section 6, RFC 9525).

//! A caller's check of the server's certificate chain, and the error of a
//! refused certificate.

use std::{error::Error as StdError, fmt, sync::Arc};

use btls::{ssl::SslRef, x509::X509VerifyError};
use tower::BoxError;

/// A caller's check of the server's certificate chain, run once per new TLS
/// connection after the handshake (and its own chain and name verification)
/// succeeded, and before the connection carries any request byte.
pub trait CertVerifyHook: Send + Sync {
    /// Checks `chain` (DER, the server's certificate first, as the server
    /// sent it) for `server_name` (the host the connection was made for). An
    /// error refuses the certificate: the connection is closed and the
    /// request fails with a [`CertificateRefused`] holding this error.
    fn verify(
        &self,
        chain: &[&[u8]],
        server_name: &str,
    ) -> Result<(), Box<dyn StdError + Send + Sync>>;
}

/// A shared [`CertVerifyHook`].
pub type CertVerifyHookRef = Arc<dyn CertVerifyHook>;

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

    /// The handshake error `source`, wrapped when the handshake's own
    /// verification failed on `ssl`; any other failure stays as it is. A
    /// handshake that failed before verifying reports `INVALID_CALL`.
    pub(crate) fn from_handshake(ssl: &SslRef, source: BoxError) -> BoxError {
        match ssl.verify_result() {
            Err(verify_error) if verify_error != X509VerifyError::INVALID_CALL => Box::new(Self {
                verify_error: Some(verify_error),
                source,
            }),
            Ok(()) | Err(_) => source,
        }
    }

    /// Runs `hook` on `ssl`'s peer chain for `server_name`.
    pub(crate) fn check(
        hook: &dyn CertVerifyHook,
        ssl: &SslRef,
        server_name: &str,
    ) -> Result<(), BoxError> {
        let der = ssl
            .peer_cert_chain()
            .into_iter()
            .flatten()
            .map(|cert| cert.to_der())
            .collect::<Result<Vec<_>, _>>()?;
        let chain: Vec<&[u8]> = der.iter().map(Vec::as_slice).collect();
        hook.verify(&chain, server_name).map_err(|source| {
            Box::new(Self {
                verify_error: None,
                source,
            }) as BoxError
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
