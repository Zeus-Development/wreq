# Viper's wreq fork: patch ledger of wreq

This repository holds the Viper project's copies of two crates from two
upstream repositories, each on its own branch: `viper/wreq-0.16.1` (this branch)
carries [wreq](https://github.com/0x676e67/wreq) and `viper/wreq-proto-0.2.6`
carries [wreq-proto](https://github.com/0x676e67/wreq-proto). Each
`viper/*` branch carries a small set of generic patches on top of the exact
sources of a published release. Viper builds each crate from one exact
commit of its branch, through a Cargo `[patch.crates-io]` entry.

This file is the canonical ledger of this branch's patches. It holds the
verified base, one row and one section per patch, the rebase procedure and
the rebase and pin logs. Viper's own record of the fork (how the pins move,
the gate step that checks them, the cargo-deny source and the licence
obligations) is its ADR 0034, "The wreq fork".

Base: 63429b4229f88adf6f1a71d7c3ffa62b5947f38c
Branch: viper/wreq-0.16.1

## Rules

- **Branches.** One long-lived branch per crate and release,
  `viper/<crate>-<version>`, created at the commit the published crate names
  and, where the crate was published from a modified checkout, one commit
  that makes the crate's tree equal to the published sources (the base
  below). A `viper/*` branch is never force-pushed, and never deleted while
  any Viper revision pins a commit on it (a repository ruleset blocks both).
- **Markers.** Every changed hunk carries `VIPER-PATCH(<id>)` in a comment
  (`//` in Rust, `#` in TOML), with `<id>` matching `[a-z0-9-]+` and naming a
  row of the ledger below. The comment states the rule implemented or the
  problem fixed, with the specification where one exists. Every file that
  differs from the base, apart from this one, carries a marker. Viper's gate
  step `wreq-fork` fails when the marker ids in the pinned commit differ
  from the ledger ids, or when a changed file carries no marker.
- **Size.** Each patch is small (target at most 100 changed code lines) and
  self-contained, one commit per patch where possible.
- **Tests.** Every patch has tests in the fork (listed in its row) and a
  proof in Viper's gate: a named Viper test that must pass in the gate's run.
- **Upstream.** Each patch is generic and may be offered upstream; nothing
  goes to an upstream repository without the Viper owner's go-ahead for that
  specific draft. A patch is dropped when upstream releases an equivalent.
- **Licences.** wreq is Apache-2.0-licensed (`LICENSE`); patched files
  keep their notices, the licence file is unchanged, and each `VIPER-PATCH`
  marker is also the notice of change that Apache-2.0 section 4(b) asks for.
- **Commits** use the Viper owner's GitHub noreply identity.

## Base

`viper/wreq-0.16.1` starts at wreq commit
`63429b4229f88adf6f1a71d7c3ffa62b5947f38c` ("chore: release v0.16.1
(#1260)"), which the published crate names. Verified on 2026-10-24:

| Crate | Published `.crate` SHA-256 (equals the crates.io index `cksum` and Viper's former `Cargo.lock` checksum) | `.cargo_vcs_info.json` | Sources compared with the base |
| --- | --- | --- | --- |
| `wreq` 0.16.1 | `16454175c8cb23d4a7285bab53b72460686195f5aef655d1abad70ab97ef46d4` | `sha1` `63429b4229f88adf6f1a71d7c3ffa62b5947f38c`, not dirty, `path_in_vcs` empty (the repository root) | identical: every packaged file, and `Cargo.toml.orig` equals the root `Cargo.toml`. Generated at packaging time and not compared: the normalized `Cargo.toml`, `Cargo.lock`, `.cargo_vcs_info.json`. The crate's `include` list leaves out the rest of the repository (tests, examples, benches) |

wreq's manifest takes `wreq-proto` and `wreq-rt` from the registry by
version, so neither is built from this branch; Viper's `[patch.crates-io]`
entry takes `wreq-proto` from the branch `viper/wreq-proto-0.2.6`.

## Ledger

| Id | Reason | Register entry | Tests | Licence and upstream attribution | Upstream status |
| --- | --- | --- | --- | --- | --- |
| `typed-proxy-errors` | a failed connection through a proxy carries a public typed error, `ProxyFailure`, whose kind says what failed (the `CONNECT` status, each SOCKS5 reply code, the I/O error kept below it) | `adr:net-proxy-error-detail` | fork: `tests/viper_patches.rs`; Viper: `viper-net::proxy proxy_failures_fail_once_before_the_origin` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `verify-hook` | a caller's check of the server's certificate chain runs after the handshake's own verification and before any request byte, and a refused certificate is a public typed error, `CertificateRefused`, holding the verification result or the hook's error (RFC 5280 section 6, RFC 9525) | `adr:net-tls-verify-detail` | fork: `tests/viper_verify_hook.rs`; Viper: `viper-net::cert_verifier a_verifiers_refusal_fails_with_its_cause_before_any_request_byte` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `proxy-alpn` | a proxy may carry an ALPN list (RFC 7301), offered in order on the TLS connection to an HTTPS proxy that tunnels with `CONNECT`; without one nothing is offered, as before | none | fork: `tests/viper_h2_proxy.rs`; Viper: `viper-net::proxy_h2 a_proxy_that_refuses_h2_gets_an_http1_tunnel` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `h2-proxy-connect` | when that proxy selects `h2`, each tunnel is a `CONNECT` stream of one HTTP/2 connection to the proxy, shared by the client's tunnels through it while it stays open (RFC 9113 section 8.5); another selection, or none, gets an HTTP/1.1 `CONNECT` on that connection | none | fork: `tests/viper_h2_proxy.rs`; Viper: `viper-net::proxy_h2 two_tunnels_share_one_http2_connection_to_the_proxy` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `connection-reuse` | a request that failed on a connection checked out of the pool says so (`Error::is_connection_reused`), and a request may ask for a new connection instead of an idle one (`RequestBuilder::new_connection`; over HTTP/2 with the limits in its section), so a client can send an idempotent request again on a new connection after its connection closed before the response (RFC 9112 section 9.3.1, RFC 9110 section 9.2.2) | none | fork: `tests/viper_connection_reuse.rs`; Viper: `viper-net::resend a_reused_connection_closed_before_the_response_is_sent_again` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `async-verify-evidence` | the caller's certificate check runs inside the handshake, as the TLS library's custom verification after the library's own chain and name verification (mirrored exactly), sees the stapled OCSP response (RFC 6066 section 8) and the SCT list of the TLS extension (RFC 6962 section 3.3), and may answer later through a future, the handshake waiting without blocking its thread (the library's `ssl_verify_retry`); its refusal ends the handshake with an alert, before any request byte | none | fork: `tests/viper_verify_hook.rs`; Viper: `viper-net::cert_verifier a_later_answer_lets_another_sessions_fetch_complete_meanwhile` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `pool-preconnect` | a client may open connections to an origin ahead of its requests (`Client::preconnect`): each takes the route a request with the client's own options takes (connector, proxy tunnel, TLS), joins the pool as an idle connection within its limits and reports its outcome, and a later request checks it out as any idle connection (HTML's `preconnect` link type) | none | fork: `tests/viper_pool_preconnect.rs`; Viper: `viper-net::preconnect a_preconnected_connection_serves_the_next_request` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `version-fields` | a request's fields may stay on its head only on a connection of listed HTTP versions (`RequestBuilder::version_fields`): once the connection is checked out, they are taken out of the head of a connection of another version, the other fields keeping their order, so a field meant for some versions only (RFC 9218's Priority) follows the version an ALPN offer of several protocols leaves to the server (RFC 7301 section 3.2) | none | fork: `tests/viper_version_fields.rs`; Viper: `viper-net::priority_versions an_https_head_offering_both_protocols_follows_the_version_the_server_picks` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `grouped-preconnect` | `Client::preconnect` may open its connections in a request group (`Group`), keyed as a request of that group is, so only such a request takes them; without one nothing changes | none | fork: `tests/viper_pool_preconnect.rs`; Viper: `viper-net::preconnect a_grouped_preconnect_serves_only_its_groups_requests` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `connector-layer-identity` | a connector layer can read the origin each connection is made for (`Unnameable::uri`) and give the connection a value it holds until it is dropped (`Conn::with_guard`); `Conn` and `Unnameable` are exported so a layer can name them | none | fork: `tests/viper_connector_layer.rs`; Viper: `viper-net::preconnect a_connector_layer_reads_the_origin_and_its_guard_drops_with_the_connection` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `connect-challenge-fields` | an HTTP proxy's 407 answer to `CONNECT`, over HTTP/1.1 or as an HTTP/2 stream, keeps its fields on the failure (`ProxyFailure::headers`), its `Proxy-Authenticate` challenges among them, so a caller can answer them (RFC 9110 sections 15.5.8 and 11.7.1) | `cdp:fetch-proxy-auth-tunnel` | fork: `tests/viper_connect_challenge.rs`, `tests/viper_h2_proxy.rs`; Viper: `viper-net::intercept_proxy a_tunnels_407_pauses_and_its_answer_goes_on_the_connect` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `request-connect-fields` | a request may set the fields of the `CONNECT` that opens its own tunnel (`RequestBuilder::connect_headers`), in place of the proxy's of their names, its tunnel keyed apart in the pool, so a caller answers a proxy's challenge on that request's tunnel only (RFC 9110 sections 9.3.6 and 11.7.2) | `cdp:fetch-proxy-auth-tunnel` | fork: `tests/viper_h2_proxy.rs`; Viper: `viper-net::intercept_proxy a_routes_refused_credentials_give_way_to_the_answer_on_the_connect` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `connect-head-fields` | a request may set the order and case of the fields of its tunnel's `CONNECT` head (`RequestBuilder::connect_order`), `Host` among them, part of its tunnel's key, so a client writes that head as a browser does; over HTTP/2 the order holds and names stay lower case (RFC 9113 section 8.2.1) | none | fork: `tests/viper_connect_head.rs`, `tests/viper_h2_proxy.rs`; Viper: `viper-net::proxy_connect a_policys_connect_plan_is_written_in_its_order_and_case` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `proxy-hello-options` | the hello to an HTTPS proxy carries the per-connection options of an origin's (SNI and hostname settings, ECH GREASE, the AES override, ALPS with its code point, the key shares and, with `trust-anchors`, the trust anchor IDs), so a client's proxy hello is the one its origin hellos are; the proxy's ALPN and the origin's session stay apart | none | fork: `tests/viper_hello_options.rs`; Viper: `viper-net::proxy_https a_proxys_hello_carries_the_profiles_per_connection_options` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `trust-anchors` | `TlsOptions::trust_anchor_ids` requests trust anchor IDs (draft-ietf-tls-trust-anchor-ids) in every hello, an origin's or a proxy's, through BoringSSL's `SSL_set1_requested_trust_anchors`; an empty or longer-than-255-byte ID fails the connector's build | none | fork: `tests/viper_hello_options.rs`; Viper: `viper-net::wreq_pin a_hello_requests_the_trust_anchor_ids_of_its_options` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `preconnect-connect-fields` | `Client::preconnect_with_connect_fields` opens connections ahead with the tunnel fields and order a request sets (`connect_headers`, `connect_order`), so a preconnected tunnel is keyed and written as that request's and the request takes it | none | fork: `tests/viper_h2_proxy.rs`; Viper: `viper-net::wreq_pin a_preconnected_tunnel_with_connect_fields_serves_the_request` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `negotiated-alpn` | `Conn::negotiated_h2` tells a connector layer whether a connection it made negotiated HTTP/2 through ALPN (RFC 7301), so a layer racing connections to one origin can give up the others once one is shared | none | fork: `tests/viper_h2_proxy.rs`; Viper: `viper-net::wreq_pin a_connector_layer_reads_whether_a_connection_negotiated_http2` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `local-port-bind` | a caller may choose each TCP socket's source port (`ClientBuilder::tcp_source_port`): asked with the peer (a proxy's address for a connection through it) and the try number, the port is bound before connect, asked again on `EADDRINUSE` or `EACCES`, and left to the OS once the caller answers `None`; a connector layer reads a connection's local and peer addresses (`Conn::addresses`), so a browser that randomizes source ports per peer can do so and learn when each closes | none | fork: `tests/viper_source_port.rs`; Viper: `viper-net::wreq_pin a_source_port_function_binds_each_socket_before_connect` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `ws-tunnel` | a request may force its connection through an HTTP or HTTPS proxy to be a `CONNECT` tunnel for an `http` URL too (`RequestBuilder::force_tunnel`), with no TLS inside the tunnel, the request in origin form and without the proxy's credentials, keyed apart in the pool, so a WebSocket client tunnels a `ws:` handshake as RFC 6455 section 4.1 recommends | `adr:net-websocket-http-proxy` | fork: `tests/viper_ws_tunnel.rs`; Viper: `viper-net::websocket a_ws_handshake_through_an_http_proxy_goes_through_a_tunnel` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `connect-superseded` | a connector layer can read the key a connection will be pooled under (`Unnameable::pool_key`, an opaque `PoolKey`) and give up an attempt with `Superseded` once another of its key negotiated HTTP/2; the request, or preconnect, then waits for the connection that won instead of failing, or starts again when no connection of its key is being made or idle | `adr:net-request-race-abort` | fork: `tests/viper_h2_proxy.rs`; Viper: `viper-net::preconnect_race a_requests_attempt_is_given_up_once_another_negotiates_h2` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `connect-407-retry` | an HTTP proxy's 407 answer to a tunnel's HTTP/1.1 `CONNECT` that leaves the connection open (HTTP/1.1 without `Connection: close`, a `Content-Length` of at most 64 KiB and no `Transfer-Encoding`; RFC 9112 sections 9.3 and 6.3) keeps it, its body read, on the failure (`ProxyFailure::connection`, a `ProxyConnection`), and a retry with credentials given it (`RequestBuilder::proxy_connection`) writes its `CONNECT` on it when it goes through the same proxy to the same authority (RFC 9110 section 15.5.8); it closes when the last handle drops, or 30 seconds after the 407 | none | fork: `tests/viper_connect_retry.rs`; Viper: `viper-net::proxy_auth_retry an_http1_tunnels_retry_goes_on_the_connection_its_407_came_on` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `h2-proxy-profile` | the HTTP/2 connection to a proxy that selected `h2` opens with the client's HTTP/2 options (`ClientBuilder::http2_options`: SETTINGS and their order, the connection window, the HEADERS priority and pseudo-header order), as its connections to origins do, instead of wreq-proto's defaults | none | fork: `tests/viper_h2_proxy.rs`; Viper: `viper-net::proxy_auth_retry an_http2_tunnels_retry_is_a_new_stream_of_a_connection_opened_as_chromes` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `h2-proxy-addresses` | each tunnel over a shared HTTP/2 proxy connection gives that connection's socket addresses through `Connected`, so `Conn::addresses` and a response's `remote_addr` read the proxy's socket as through an HTTP/1.1 tunnel, never the proxy's ALPN | `adr:net-source-port-h2-proxy` | fork: `tests/viper_h2_proxy.rs`; Viper: `viper-net::proxy_h2 an_http2_proxy_connections_source_port_is_held_while_it_is_open` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |

## typed-proxy-errors

wreq's tunnel and SOCKS errors (`TunnelError`, `SocksError`) are private
types, a `CONNECT` refused with a status kept no status, and the SOCKS error
kept no cause, so a caller could tell failures apart only by their
messages. With the patch, the connector wraps each proxy failure in the
public `ProxyFailure` (`src/conn/proxy/failure.rs`, exported as
`wreq::ProxyFailure` and `wreq::ProxyFailureKind`), found in the source
chain of an error whose `is_proxy_connect` is true. Its kind is one of:
`Connect` (the connection to the proxy failed; its I/O error is below it
in the chain), `Status` (the `CONNECT` answer's status, RFC 9110 section
9.3.6), `Socks5Reply` (RFC 1928 section 6, 1 to 8),
`Socks5NoAcceptableMethods` (RFC 1928 section 3), `Socks5AuthRejected`
(RFC 1929), `Malformed`, `Closed` (the proxy ended the connection, an end
of file, before its reply, for `CONNECT` and SOCKS5 alike), `Handshake`
(another I/O error during the handshake, below it in the chain) and `Other`. The SOCKS error keeps its cause as its source. The
wrapped errors' messages are unchanged; the forwarding proxy's connection
failure (http origins) is wrapped too, as `Connect`.

## verify-hook

wreq verified a server's certificate only through the TLS library's own
chain and name verification, offered no hook between the handshake and the
first request byte, and dropped the handshake's state on failure, so a
caller could neither add its own check nor tell why a certificate was
refused. With the patch, `ClientBuilder::tls_verify_hook` takes a
`CertVerifyHook` (`src/tls/verify.rs`, public as
`wreq::tls::verify`), which the TLS connector (`src/tls/conn/service.rs`)
calls once per new connection, a resumed one included, after the handshake
succeeded and before the stream is handed out, with the peer's chain in
DER (the leaf first, as sent) and the host the connection was made for. Its
error refuses the connection with `CertificateRefused`, whose source is the
hook's error. A handshake that the library's own verification refused
fails with `CertificateRefused` too, holding the verification result
(`verify_error`) and the handshake error as its source; a handshake that
failed before verifying (the result is `INVALID_CALL`) or after it
succeeded is unchanged, and so is any failure with verification off (the
library still verifies then, but its result never ends the handshake).
Without a hook nothing else changes.
Since `async-verify-evidence` the hook runs inside the handshake, with the
handshake's evidence, and may answer later (that patch's section).

## proxy-alpn

wreq offered no ALPN on the TLS connection to an HTTPS proxy (the
connector disabled it there), so a tunnel always spoke HTTP/1.1 to the
proxy. With the patch, `Proxy::alpn_protocols` (`src/proxy.rs`) stores a
list on the proxy, part of its identity like its credentials. The
connector (`src/conn/connector.rs`) hands it to the TLS connector
(`HttpsConnector::proxy_alpn`, `src/tls/conn.rs`), which offers it, in
order, when it connects to the proxy's URI. It is used only for tunnels
(`https` destinations): requests forwarded to the proxy for `http`
destinations keep no ALPN and HTTP/1.1. Without a list nothing changes.

## h2-proxy-connect

wreq-proto's HTTP/2 client already sends `CONNECT` (an `:authority` and no
`:scheme` or `:path`) and turns a 200 answer into an upgraded byte stream,
but wreq's connector never used it for a proxy. With the patch
(`src/conn/proxy/h2.rs`), a tunnel through an HTTPS proxy with an ALPN list
first looks for an open HTTP/2 connection to the same proxy, then opens
one: TLS with the list, and, when the proxy selected `h2`, the HTTP/2
handshake with wreq-proto's default settings, the connection driven on the
runtime's executor. Each tunnel is a `CONNECT` stream on it, carrying the
proxy's credentials and headers; the destination's TLS runs inside the
stream. A closed connection is dropped at the next lookup; two tunnels
opened at the same moment may each open one. When the proxy selected
another protocol or none, the HTTP/1.1 `CONNECT` runs on the connection
just made (`TunnelConnector::tunnel_over`, `src/conn/proxy/tunnel.rs`).
Failures are `ProxyFailure`s with the HTTP/1.1 tunnel's kinds: the
connection to the proxy (`Connect`), an answer other than 200 (`Status`,
407 included), and a stream or connection failure after the connection
was made, such as a reset stream (`Handshake`, with the HTTP/2 error below
it in the chain).

## connection-reuse

wreq retried a request only when it was never written to its connection
(`retry_canceled_requests`, on a reused connection). A request that was
written to a pooled connection the peer had closed while it was idle failed
with the pool's `is_reused()` dropped, and every request checked out an
idle connection first, so a caller could neither tell such a failure apart
nor make sure a second attempt went to a new connection. With the patch,
the client layer's error (`src/client/layer/client.rs`) keeps whether the
failed request's connection came out of the pool, read through
`wreq::Error::is_connection_reused` (`src/error.rs`), and
`RequestBuilder::new_connection` (`src/client/request.rs`, a per-request
option in `src/client/layer/config.rs`) makes the client connect instead
of checking out an idle connection. Over HTTP/1 the new connection then
joins the pool as usual. Over HTTP/2 the pool keeps one connection per
destination: the new connection joins it only when none is idle, and while
another HTTP/2 connection to the destination is being made the request
falls back to the usual race, which may give it that connection or the
pooled one, and a failure there is reported as reused. RFC 9112 section
9.3.1, the case the patch serves, is HTTP/1.1. Nothing else changes:
a request without the option uses the pool as before, and wreq's own
retries are unchanged.

## async-verify-evidence

The `verify-hook` patch ran the caller's check after the handshake, on its
own, with the chain and the host only, and its answer had to be ready when
the call returned. A check that needs the handshake's stapled OCSP response
or its signed certificate timestamps could not get them, and a check that
fetches something (an intermediate certificate, a revocation status) would
have blocked the connection's thread. With the patch, `CertVerifyHook::verify`
also receives a `HandshakeEvidence` (`src/tls/verify.rs`): the OCSP response
the server stapled (RFC 6066 section 8; in TLS 1.3 the leaf's
`status_request` extension of its `CertificateEntry`, RFC 8446 section 4.4.2) and the body of the
`signed_certificate_timestamp` extension (RFC 6962 section 3.3), each as
received and present only when the client asked for it and the server sent
it. It returns a `CertVerifyFuture` instead of a result.

The TLS connector (`src/tls/conn/service.rs`) installs the hook on each
connection as the library's custom verification (`SSL_set_custom_verify`,
keeping the connection's verify mode), so it runs inside the handshake.
Because a custom verification replaces the library's own, the callback
first runs the library's own verification exactly as the library runs it
without one (`ssl_crypto_x509_session_verify_cert_chain`, client side: the
context's trust store, since the connector sets no separate verify store;
the `ssl_server` defaults; the connection's verification parameters, its
host among them; the public name after a refused ECH offer; the same alert
for a failure; the error queue cleared when the library clears it). A
refusal there ends the handshake as before, and `CertificateRefused` keeps
its verification result; a failure to set the verification up ends it
whatever the verify mode, with the handshake's error unchanged, as in the
library. So does a chain that cannot be encoded. A panic of the hook, which
cannot unwind through the library's callback, is caught there, ends the
handshake and is resumed in the connecting task, as before the patch. Then it calls the hook and polls its future with
the waker of the task driving the handshake. While the future is pending,
the callback returns `ssl_verify_retry`, the handshake returns
`WANT_CERTIFICATE_VERIFY`, and the connector waits until the future wakes
it, so the thread serves other connections meanwhile. The hook's refusal
ends the handshake with the library's default alert for a custom refusal
(`certificate_unknown`), before the client's `Finished`, so before any
request byte. With verification off the library ignores a failed custom
verification (as it ignores its own), so the hook's refusal ends the
connection right after the handshake, as with `verify-hook`. A resumed
handshake verifies nothing again, so on a resumed connection the hook
checks the session's chain, with the session's evidence, after the
handshake and before the stream is handed out, as with `verify-hook`.

What changes from `verify-hook`: the check runs inside the handshake
rather than after it, so a server sees a refusal as an alert rather than a
closed connection after a completed handshake; and with a hook,
`SslRef::verify_result` reports `X509_V_OK` after a successful custom
verification, the library's convention, rather than its own result (with
verification off, its own failure). Nothing reads that result outside the
refusal path, where `CertificateRefused` keeps the library's own. Without a
hook nothing changes: the handshake is driven as before. The patch adds the
`foreign-types` dependency, already in the graph through `btls`, for the
library's raw pointers.

## pool-preconnect

wreq's pool filled only when a request was sent: a connection was made for
a request and joined the pool once the request no longer needed it. A
client that knows it will soon fetch from an origin (HTML's `preconnect`
link type, a navigation's early connections) could not open connections
ahead. With the patch, `Client::preconnect(uri, count)` (`src/client.rs`)
opens `count` new connections to the origin of `uri` through the client's
connection layer (`HttpClient::preconnect`, `src/client/layer/client.rs`),
which `Client` now keeps beside its service: each goes through the
connector with the request options a request without its own options has,
so the proxy chosen for `uri` and its tunnel and TLS are the request's, and
skips the idle connections as `new_connection` does. Once it is ready for a
request it is dropped into the pool as an idle connection, where the
pool's limits apply (`pool_max_idle_per_host` closes the ones past it,
`pool_idle_timeout` the ones left idle). Each connection's outcome is
reported in order: `Ok`, or the error a request would have got connecting,
with the URI. Over HTTP/2 the pool keeps one connection per destination,
so the connections share the one being made. A request with its own
options (a proxy, TLS options, a version, a group) has another pool key
and does not take them. Nothing else changes: without a call the pool
fills as before.

## version-fields

A request's fields were fixed before its connection was checked out, but
the HTTP version of that connection is known only after checkout when the
client offers several protocols through ALPN and the server picks one (RFC
7301 section 3.2). A field meant for some versions only, such as RFC 9218's
`Priority` for a client that writes it on HTTP/2 alone, could not be left
out of the others' heads. With the patch,
`RequestBuilder::version_fields(versions, headers)` (`src/client/request.rs`)
adds the fields as `RequestBuilder::headers` does, in place of any of the
same names, and keeps them beside the request (`VersionFields`,
`src/client/layer/config.rs`). Once `try_send_request`
(`src/client/layer/client.rs`) has the connection, it fits the head to the
connection's version, `HTTP_2` or `HTTP_11` for an HTTP/1 connection: on a
listed version the fields stay; on another the fields of their names are
taken out and the others keep their order (the map is rebuilt, since a
`HeaderMap` removal moves its last field). A retry on another connection
fits the head again, putting the fields back at its end on a listed
version. Nothing else changes: without the call a request is as before.

## grouped-preconnect

wreq partitions its pool by request group (`RequestBuilder::group`), but
`pool-preconnect`'s `Client::preconnect` opened its connections with the
options of a request of no group, so a client that partitions its
connections could not open them ahead in a partition. With the patch
`Client::preconnect(uri, count, group)` (`src/client.rs`) takes an optional
`Group`: `HttpClient::preconnect` (`src/client/layer/client.rs`) adds it to
the connection's group as `RequestBuilder::group` adds a request's, so the
connections are keyed as a request of that group is and only such a
request takes them. Without one nothing changes.

## connector-layer-identity

A connector layer (`ClientBuilder::connector_layer`) wraps the service that
makes each connection, but that service's request (`Unnameable`) and
response (`Conn`) were not named outside the crate, the request did not say
what the connection is for, and a connection had no place for a layer's
value. A layer could not count an origin's open connections. With the
patch (`src/conn.rs`, `src/conn/connector.rs`, `src/lib.rs`),
`Unnameable::uri` gives the origin the connection is made for (its scheme,
host and port, the path `/`), `Conn::with_guard` keeps a value until the
connection is dropped (when it closes, or when the pool drops it; a second
guard replaces the first), and `Conn` and `Unnameable` are exported, so a
layer can name them. Nothing else changes: a connection without a guard is
as before.

## connect-challenge-fields

An HTTP proxy that answered a tunnel's `CONNECT` with 407 ended it as
`TunnelError::ProxyAuthRequired` with nothing of its head, so a caller could
not read the `Proxy-Authenticate` challenges it must answer (RFC 9110
sections 15.5.8 and 11.7.1). With the patch, the HTTP/1.1 tunnel
(`src/conn/proxy/tunnel.rs`) keeps the 407's parsed fields, a field that is
not valid left out, and the HTTP/2 `CONNECT` stream (`src/conn/proxy/h2.rs`)
its response's fields, in `TunnelError::ProxyAuthRequired`; the conversion
to `ProxyFailure` moves them to the failure, whose `ProxyFailure::headers`
(`src/conn/proxy/failure.rs`) gives them, `None` for every other failure.
The status line's reason phrase and version are not kept. Nothing else
changes.

## request-connect-fields

A tunnel's `CONNECT` fields came only from the proxy's configuration
(`Proxy::basic_auth`, `Proxy::custom_http_headers`), so a client answering
a proxy's challenge to one request's `CONNECT` (RFC 9110 sections 9.3.6 and
11.7.2) needed a second client or a per-request proxy. With the patch,
`RequestBuilder::connect_headers(headers)` (`src/client/request.rs`) keeps
the fields with the request (`ConnectFields`, `src/client/layer/config.rs`);
`HttpClient` (`src/client/layer/client.rs`) gives them to the connection's
descriptor (`src/conn/descriptor.rs`), which adds them to the connection's
group (`src/group.rs`), hashed by name in sorted order and then each name's
values in order, as `HeaderMap`'s equality compares them, so a tunnel
opened with them serves only requests with the same fields. The connector
(`src/conn/connector.rs`) merges them over the proxy's own fields on the
HTTP/1.1 `CONNECT`, and `proxy::h2::open` on the HTTP/2 `CONNECT` stream,
each replacing the proxy's fields of their names. A forwarded request, a
SOCKS proxy, a Unix socket and a direct connection do not send them, and a
preconnect sets none. Without the call nothing changes.

## connect-head-fields

A tunnel's HTTP/1.1 `CONNECT` head always wrote `Host` right after the
request line and every other field in lower case (`HeaderName::as_str`),
in its map's order, so a client could not write the head a browser writes
(Chrome: `Host`, `Proxy-Connection`, `User-Agent`). With the patch,
`RequestBuilder::connect_order(order)` (`src/client/request.rs`) keeps an
`OrigHeaderMap` with the request's `ConnectFields`
(`src/client/layer/config.rs`), whose hash and equality take each
spelling in order too (`OrigHeaderMap`'s own equality ignores the order of
its names), so a tunnel opened with one order serves only requests with the
same order.
The connector (`src/conn/connector.rs`) gives it, through the descriptor
(`src/conn/descriptor.rs`), to the HTTP/1.1 tunnel
(`src/conn/proxy/tunnel.rs`), which writes `Host` and the head's fields
(the proxy's credentials and custom headers, the request's own over them)
through `OrigHeaderMap::call_visit`: the named fields first, in the order's
order and spelling, then the others in lower case; `Host` goes where the
order places it, or first when it does not name it, and only once. The
HTTP/2 `CONNECT` stream (`src/conn/proxy/h2.rs`) sorts its fields by the
same order, names in lower case (RFC 9113 section 8.2.1). Without the call
nothing changes, byte for byte.

## proxy-hello-options

`TlsConnector::setup_ssl` (`src/tls/conn.rs`), which makes the SSL object
of the TLS connection to an HTTPS proxy, set only the proxy's ALPN list, so
that hello carried none of the per-connection options `setup_ssl2` sets on
an origin's: SNI and hostname verification as configured, ECH GREASE, the
random AES override, ALPS with its code point and the key shares. A client
copying a browser's hello thus sent a different one to its proxy. With the
patch both call `hello_options`, which sets them all (and, with
`trust-anchors`, the trust anchor IDs); the proxy keeps its own ALPN list,
and the origin's version-dependent ALPN and session resumption stay the
origin's. BoringSSL sends ALPS only with ALPN, so a proxy offered no ALPN
gets none.

## trust-anchors

`TlsOptions::trust_anchor_ids` (`src/tls.rs`), with its builder method,
holds the trust anchor IDs a client requests (draft-ietf-tls-trust-anchor-ids
section 4.1): each an opaque, non-empty ID of at most 255 bytes. The
connector's build (`src/tls/conn.rs`) encodes them once in the wire format
BoringSSL takes (each ID with an 8-bit length), refusing an invalid one as a
builder error, and `hello_options` sets them on every SSL object, an
origin's or a proxy's, through btls-sys's `SSL_set1_requested_trust_anchors`
at the version wreq links (one `unsafe` call; the library copies the bytes).
An empty list sends the extension empty; `None`, the default, sends none.

## preconnect-connect-fields

`Client::preconnect` (`src/client.rs`, the patches `pool-preconnect` and
`grouped-preconnect`) keyed its connections with no tunnel fields, so
through an HTTP proxy a preconnected tunnel had neither the `CONNECT`
fields nor the order a request sets (`request-connect-fields`,
`connect-head-fields`) and a request with them never took it.
`Client::preconnect_with_connect_fields(uri, count, group, headers, order)`
gives the layer's `preconnect` (`src/client/layer/client.rs`) the same
`ConnectFields` a request with `connect_headers(headers)` and, with an
order, `connect_order(order)` gets, so the connection is keyed and its
`CONNECT` written as that request's. `preconnect` is unchanged.

## negotiated-alpn

A connector layer (`ClientBuilder::connector_layer`) gets each connection
as a `Conn` and could not see the protocol it negotiated: `Connection` and
`Connected` are not exported. `Conn::negotiated_h2` (`src/conn.rs`) tells
whether the transport under it negotiated `h2` through ALPN; false for
HTTP/1.1, no ALPN or plain text. A layer racing several connections to one
origin can give up the others as soon as one negotiated HTTP/2, which the
pool shares.

## local-port-bind

wreq opens and binds every TCP socket itself (`src/conn/net/tcp.rs`):
with a local address configured it binds that address with port 0, so the
OS always picks the source port, and the TCP connector is not
replaceable. A browser that picks its own source ports (Chrome's
`EphemeralPortRandomizer` on macOS, a uniform port per publicly routable
peer, with up to five tries) could not be followed. With the patch
(`src/client.rs`, `src/conn/http.rs`, `src/conn/net.rs`,
`src/conn/net/tcp.rs`),
`ClientBuilder::tcp_source_port` takes a function asked for each socket
with its peer and the try number, 0 first; its port is bound, on the
configured local address of the peer's family or the unspecified one,
before connect. A port in use or not allowed (`EADDRINUSE`, `EACCES`) asks
again with the next try number; once the function answers `None` the
socket is bound as before. A connection through a proxy asks with the
proxy's address: the socket only ever reaches the proxy. `Conn::addresses`
(`src/conn.rs`) gives a connector layer the local and peer addresses of
the socket under a connection, so the caller can learn when a chosen port
is released. Without the function nothing changes.

## ws-tunnel

wreq tunnels through an HTTP or HTTPS proxy only for an `https`
destination (`src/conn/connector.rs`); an `http` one is forwarded in
absolute form with the proxy's credentials on the request. RFC 6455
section 4.1 asks a WebSocket client to tunnel a `ws:` handshake with
`CONNECT` through an HTTP proxy, as browsers do, since a proxy may not
forward an `Upgrade`. With the patch, `RequestBuilder::force_tunnel(true)`
(`src/client/request.rs`) sets a flag in the request's `ConnectFields`
(`src/client/layer/config.rs`), which keeps it next to the tunnel's fields
and order (each setter keeps the others) and compares and hashes it, so a
forced tunnel's connection is keyed apart from a forwarded one's in the
pool. The descriptor (`src/conn/descriptor.rs`) reads it, and the
connector takes its tunnel branch when the destination is `https` or the
flag is set; for an `http` destination the HTTPS connector adds no TLS
inside the tunnel, and the connection, like every tunnel, is not marked
proxied, so the request goes in origin form with no `Proxy-Authorization`.
A preconnect sets no flag (`src/client.rs`). An `https` URL, a SOCKS proxy,
a Unix socket and no proxy are unchanged, and so is everything without the
call.

WREQ-FORK-5 adds the two follow-ups of WREQ-FORK-3's review: fields left
all default after `force_tunnel(false)` are no fields, so such a request
pools with one that never called it (`tests/viper_ws_tunnel.rs`), and a
fork test of a forced tunnel to an `http` destination through an HTTPS
proxy that negotiates HTTP/2, a `CONNECT` stream as any other
(`tests/viper_h2_proxy.rs`).

## connect-superseded

A connector layer racing several attempts to one destination, as a browser
gives up its in-flight attempts once an HTTP/2 session exists, could give
one up only by failing it: `connect_to` (`src/client/layer/client.rs`)
turns every connector error into `ErrorKind::Connect`, which fails the
request, and the layer could not tell which attempts the pool treats as
interchangeable. With the patch, `Unnameable::pool_key` (`src/conn.rs`)
gives the key the connection will be pooled under, an opaque `PoolKey`
(`Clone`, `Eq`, `Hash`) holding the descriptor's `ConnectionId`, so a layer
races only attempts of one key: one of another partition, route, version
or tunnel fields could never be served by the winner. An attempt the
layer gives up fails with `wreq::Superseded`; `Error::new` turns it into
`ErrorKind::Canceled`, and both the race and a new-connection request
(`RequestBuilder::new_connection`, which `Client::preconnect` uses) then
take `Pool::superseded` (`src/client/layer/client/pool.rs`): a checkout
waiting for the HTTP/2 connection being made for the key, whose lock's
release answers the waiter either way, or taking an idle one, and `None`
when neither exists. A checkout that ends without a connection starts the
request again, as a closed checkout does (`retry_canceled_requests`), so a
superseded request never waits where no connection can come. Without the
error nothing changes.

## connect-407-retry

A browser answering a proxy's 407 to `CONNECT` retries on the connection
the 407 came on; wreq's tunnel (`src/conn/proxy/tunnel.rs`) returned
`ProxyAuthRequired` and dropped it, so a retry, a new request after the
caller found credentials, always opened another. With the patch, a 407
whose head lets the connection stay open (HTTP/1.1 without
`Connection: close`, its body framed by one `Content-Length` of at most
64 KiB and no `Transfer-Encoding`) has its body read and the connection
kept (`src/conn/proxy/kept.rs`) on the failure as a `ProxyConnection`
(`ProxyFailure::connection`), bound to the proxy (its URI, credentials,
headers and ALPN list) and the `CONNECT`'s authority. A request given it
(`RequestBuilder::proxy_connection`, carried on the connection descriptor
outside the pool key) writes its tunnel's `CONNECT` on it, in
`src/conn/connector.rs`, when its tunnel goes through that proxy to that
authority and the proxy has not closed it or sent anything since (a read
with no waker); otherwise it connects as before. Clones share the one
connection, taken once; it closes when the last is dropped, or 30 seconds
after the 407 on the runtime's timer. Over HTTP/2 the retry is already a
new stream of the shared connection. Without a handle nothing changes.

## h2-proxy-profile

The HTTP/2 connection to a proxy that selected `h2`
(`src/conn/proxy/h2.rs`, `h2-proxy-connect`) opened with
`Builder::new`'s defaults, whatever HTTP/2 options the client had. With
the patch, `ConnectorBuilder::http2_options` (set from the client's
`http2_options` in `src/client.rs`) keeps them with the shared
connections, and the handshake applies them, so the connection's SETTINGS
and their order, its window, and its HEADERS priority and pseudo-header
order are the client's, as a browser opens one to an HTTPS proxy with its
origin profile. Without options nothing changes.

## h2-proxy-addresses

A tunnel over a shared HTTP/2 proxy connection (`H2Tunnel`) reported an
empty `Connected`, so `Conn::addresses` (`local-port-bind`) and a
response's `remote_addr` had nothing, though an HTTP/1.1 tunnel reports
its socket's. With the patch, `src/conn/proxy/h2.rs` reads the TCP
socket's `HttpInfo` below the proxy's TLS when it opens the connection,
keeps it with the shared connection and gives it to each tunnel's
`Connected`, without the proxy's ALPN (`h2` is the proxy's, not the
tunnel's), so a caller can tie a chosen source port to the connection and
reads the proxy as the response's peer.

## Rebase procedure

1. A new wreq release gets a new branch, `viper/wreq-<version>`, from the
   commit its published crate names; the base verification above is
   repeated.
2. Each patch is applied again as its own commit, its markers kept, and
   dropped if upstream has an equivalent.
3. `cargo test --no-default-features --features tokio-rt,socks` and the
   fork tests pass; this file gets the new `Base:`, `Branch:`,
   verification, ledger and a rebase-log line.
4. A Viper task moves the pin; Viper's gate step `wreq-fork` checks it.

## Rebase log

| Date | From | To | Conflicts | Effort |
| --- | --- | --- | --- | --- |
| none yet | | | | |

## Pin log

| Viper task | Commit | Change |
| --- | --- | --- |
| V16d-3a | the last commit of this range | the branch and the patch `typed-proxy-errors` |
| V16d-4 | the last commit of this range | the patch `verify-hook` |
| V16d-3d | the last commit of this range | the patches `proxy-alpn` and `h2-proxy-connect` |
| NET-RESEND-1 | the last commit of this range | the patch `connection-reuse` |
| NET-CERT-SEAM-1 | the last commit of this range | the patch `async-verify-evidence` |
| WREQ-PRECONNECT-1 | the last commit of this range | the patch `pool-preconnect` |
| NET-WREQ-FORK-2 | the last commit of this range | the patches `version-fields`, `grouped-preconnect` and `connector-layer-identity` |
| CDP-FETCH-TUNNEL-AUTH-1 | the last commit of this range | the patches `connect-challenge-fields` and `request-connect-fields` |
| NET-CONNECT-FIELDS-1 | the last commit of this range | the patch `connect-head-fields` |
| WREQ-H2-PRIORITY-1 | the last commit of this range | the patches `proxy-hello-options`, `trust-anchors`, `preconnect-connect-fields` and `negotiated-alpn` |
| WREQ-FORK-3 | the last commit of this range | the patches `local-port-bind` and `ws-tunnel` |
| WREQ-FORK-5 | the last commit of this range | the patch `connect-superseded` and the follow-ups of `ws-tunnel` |
| WREQ-PROXY-CONN-1 | the last commit of this range | the patches `connect-407-retry`, `h2-proxy-profile` and `h2-proxy-addresses` |
