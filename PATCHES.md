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
