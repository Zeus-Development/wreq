use std::{
    // VIPER-PATCH(request-connect-fields): the fields' hash.
    hash::{Hash, Hasher},
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, Either, Ready};
use http::{HeaderMap, HeaderName, Request, Response, Version};
use tower::{Layer, Service};
use wreq_proto::{http1::Http1Options, http2::Http2Options};

use crate::{
    Error, config::RequestConfig, conn::net::SocketBindOptions, ext::UriExt, group::Group,
    header::OrigHeaderMap, proxy::Matcher, tls::TlsOptions,
};

/// A marker type for the default headers configuration value.
#[derive(Clone, Copy)]
pub(crate) struct DefaultHeaders;

// VIPER-PATCH(version-fields): a request's fields that stay on its head
// only when the connection it is checked out on speaks one of `versions`;
// the version is the connection's, known only after checkout (an ALPN offer
// of several protocols is decided by the server, RFC 7301 section 3.2).
/// Fields of a request kept after checkout on a connection of the listed
/// versions only.
#[derive(Debug, Clone)]
pub(crate) struct VersionFields {
    pub versions: Vec<Version>,
    pub headers: HeaderMap,
}

impl VersionFields {
    /// Fits `headers` to a connection of `version`: on a listed version the
    /// fields stay, or come back at the end after a retry took them out; on
    /// another their names are taken out, the other fields keeping their
    /// order.
    pub(crate) fn apply(&self, headers: &mut HeaderMap, version: Version) {
        if self.versions.contains(&version) {
            for (name, value) in &self.headers {
                if !headers.contains_key(name) {
                    headers.append(name, value.clone());
                }
            }
        } else if self.headers.keys().any(|name| headers.contains_key(name)) {
            let mut current = None;
            for (name, value) in std::mem::take(headers) {
                current = name.or(current);
                if let Some(name) = current.as_ref().filter(|n| !self.headers.contains_key(*n)) {
                    headers.append(name.clone(), value);
                }
            }
        }
    }
}

// VIPER-PATCH(request-connect-fields): the fields of the `CONNECT` that
// opens one request's tunnel through an HTTP proxy, part of its connection's
// key.
/// Fields of the `CONNECT` request of a request's tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
// VIPER-PATCH(connect-head-fields): and the head's order and case.
pub(crate) struct ConnectFields(pub HeaderMap, pub Option<OrigHeaderMap>);

impl Hash for ConnectFields {
    /// By name, in sorted order, then each name's values in order, as
    /// `HeaderMap`'s equality compares them.
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut names: Vec<&HeaderName> = self.0.keys().collect();
        names.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        for name in names {
            name.as_str().hash(state);
            for value in self.0.get_all(name) {
                value.as_bytes().hash(state);
            }
        }
        // VIPER-PATCH(connect-head-fields): the head's order and case.
        for (_, case) in self.1.iter().flat_map(OrigHeaderMap::iter) {
            case.hash(state);
        }
    }
}

/// Per-request configuration for proxy, protocol, and transport options.
/// Overrides client defaults for a single request.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub(crate) struct RequestOptions {
    pub group: Group,
    pub proxy: Option<Matcher>,
    pub version: Option<Version>,
    pub tls_options: Option<TlsOptions>,
    pub http1_options: Option<Http1Options>,
    pub http2_options: Option<Http2Options>,
    pub socket_bind_options: Option<SocketBindOptions>,
    // VIPER-PATCH(connection-reuse): open a new connection instead of
    // checking out an idle one.
    pub new_connection: bool,
    // VIPER-PATCH(request-connect-fields): the tunnel's `CONNECT` fields.
    pub connect_fields: Option<ConnectFields>,
}

/// Configuration for the [`ConfigService`].
struct Config {
    https_only: bool,
    headers: HeaderMap,
    orig_headers: RequestConfig<OrigHeaderMap>,
    default_headers: RequestConfig<DefaultHeaders>,
}

/// Middleware layer to use [`ConfigService`].
pub struct ConfigServiceLayer {
    config: Arc<Config>,
}

/// Middleware service to use [`Config`].
#[derive(Clone)]
pub struct ConfigService<S> {
    inner: S,
    config: Arc<Config>,
}

// ===== impl DefaultHeaders =====

impl_request_config_value!(DefaultHeaders, bool);

// ===== impl RequestOptions =====

impl_request_config_value!(RequestOptions);

// ===== impl ConfigServiceLayer =====

impl ConfigServiceLayer {
    /// Creates a new [`ConfigServiceLayer`].
    pub fn new(https_only: bool, headers: HeaderMap, orig_headers: OrigHeaderMap) -> Self {
        let org_headers = (!orig_headers.is_empty()).then_some(orig_headers);
        ConfigServiceLayer {
            config: Arc::new(Config {
                https_only,
                headers,
                orig_headers: RequestConfig::new(org_headers),
                default_headers: RequestConfig::new(Some(true)),
            }),
        }
    }
}

impl<S> Layer<S> for ConfigServiceLayer {
    type Service = ConfigService<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        ConfigService {
            inner,
            config: self.config.clone(),
        }
    }
}

// ===== impl ConfigService =====

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for ConfigService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: From<Error>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let uri = req.uri().clone();

        // check if the request URI scheme is valid.
        if !(uri.is_http() || uri.is_https()) || (self.config.https_only && !uri.is_https()) {
            return Either::Right(future::err(Error::uri_bad_scheme(uri.clone()).into()));
        }

        // check if the request ignores the default headers.
        if self
            .config
            .default_headers
            .fetch(req.extensions())
            .copied()
            .unwrap_or_default()
        {
            // insert default headers in the request headers
            // without overwriting already appended headers.
            let mut dest = self.config.headers.clone();
            crate::util::replace_headers(&mut dest, std::mem::take(req.headers_mut()));
            std::mem::swap(req.headers_mut(), &mut dest);
        }

        // store the original headers in request extensions
        if let Some(orig_headers) = self.config.orig_headers.take(req.extensions_mut()) {
            wreq_proto::ext::on_preserve_header(&mut req, orig_headers);
        }

        Either::Left(self.inner.call(req))
    }
}
