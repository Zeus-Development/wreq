# Viper's wreq fork: patch ledger of wreq-proto

This repository holds the Viper project's copies of two crates from two
upstream repositories, each on its own branch: `viper/wreq-0.16.1` carries
[wreq](https://github.com/0x676e67/wreq) and `viper/wreq-proto-0.2.6` (this
branch) carries [wreq-proto](https://github.com/0x676e67/wreq-proto). Each
`viper/*` branch carries a small set of generic patches on top of the exact
sources of a published release. Viper builds each crate from one exact
commit of its branch, through a Cargo `[patch.crates-io]` entry.

This file is the canonical ledger of this branch's patches. It holds the
verified base, one row and one section per patch, the rebase procedure and
the rebase and pin logs. Viper's own record of the fork (how the pins move,
the gate step that checks them, the cargo-deny source and the licence
obligations) is its ADR 0034, "The wreq fork".

Base: 9c455ff8314574efc9d2feb1f50fa0a9e0e3459e
Branch: viper/wreq-proto-0.2.6

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
- **Licences.** wreq-proto is Apache-2.0-licensed (`LICENSE`); patched files
  keep their notices, the licence file is unchanged, and each `VIPER-PATCH`
  marker is also the notice of change that Apache-2.0 section 4(b) asks for.
- **Commits** use the Viper owner's GitHub noreply identity.

## Base

The branch starts at wreq-proto commit
`6481a17b03abaf205a88b39a0f8dd6c5e3b07033` ("chore(deps): bump
actions/checkout from 6 to 7 (#29)"), which the published crate names. The
crate was published from a modified checkout of that commit
(`.cargo_vcs_info.json` says `"dirty": true`), so the base is the next
commit, which makes the tree under `wreq-proto/` equal to the published
sources. Verified on 2026-10-24:

| Crate | Published `.crate` SHA-256 (equals the crates.io index `cksum` and Viper's former `Cargo.lock` checksum) | `.cargo_vcs_info.json` | Sources compared with the base |
| --- | --- | --- | --- |
| `wreq-proto` 0.2.6 | `cb4d829f0427a5064829976fe790641ca21abb1d83d844812baf022dc0bdf2db` | `sha1` `6481a17b03abaf205a88b39a0f8dd6c5e3b07033`, `"dirty": true`, `path_in_vcs` `wreq-proto` | identical, byte for byte: `LICENSE` and the 33 files under `src/`, and `Cargo.toml.orig` equals `wreq-proto/Cargo.toml`; `cargo package` at the base gives the published normalized `Cargo.toml`. `README.md` differs: the repository's file is a symbolic link to the root `README.md`, and the published file holds only the link's text (`../README.md`). Generated at packaging time and not compared: the normalized `Cargo.toml`, `Cargo.lock`, `.cargo_vcs_info.json` |

The equalizing commit changes, from `6481a17b`: the workspace version (0.2.5
to 0.2.6) and tokio requirement (1.52.3 to 1.53.1) in the root `Cargo.toml`;
the `http2` (0.5.16 to 0.5.20) and dev `h2` (0.4.6 to 0.4.18) requirements in
`wreq-proto/Cargo.toml`, with its published CRLF line ends;
`current_max_send_streams` and `current_max_recv_streams` on the HTTP/2
connection (`src/conn/http2.rs`, `src/proto/http2/client.rs`); and
`src/lock.rs`'s line ends (CRLF, as published). `wreq-rt`, the repository's
other package, keeps its own version and is not built from this fork.

## Ledger

| Id | Reason | Register entry | Tests | Licence and upstream attribution | Upstream status |
| --- | --- | --- | --- | --- | --- |
| `header-count-growth` | a response head with more fields than the parser's default slots is parsed again with more slots; only the head's size bounds it (RFC 9110 and RFC 9112 set no field-count limit) | `adr:net-header-fidelity` (its field-count part) | fork: `src/proto/http1/role.rs` `viper_patch_tests`; Viper: `viper-net::fetch a_heads_size_bounds_it_and_not_its_field_count` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `content-length-values` | differing `Content-Length` values get their own parse error, told apart from an unreadable value (RFC 9112 section 6.3) | `adr:net-content-length-parse` | fork: `src/proto/http1/role.rs` `viper_content_length_tests`; Viper: `viper-net::fetch differing_content_length_values_are_told_from_an_unreadable_one` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |
| `response-bytes` | an HTTP/1 request whose connection fails before the response head is complete (an end of stream, a failed read or a failed write) learns whether any response byte had arrived, an informational response or part of the head, so a client can tell an unanswered request from a partly answered one when it decides on an automatic retry (RFC 9112 section 9.3.1, RFC 9110 section 9.2.2) | none | fork: `tests/viper_response_bytes.rs`; Viper: `viper-net::resend basic_resends_only_before_any_response_byte` | Apache-2.0 (Viper's own change) | candidate; never offered without the owner |

## header-count-growth

`Client::parse` (`src/proto/http1/role.rs`) parses a response head into a
fixed number of slots: 100 inline ones, or the count the caller set with
`Http1Options::max_headers`. A head with more fields failed with
`TooManyHeaders`, reported as a head that is too large. With the patch, when
the caller set no count, the head is parsed again with twice the slots, up
to the most fields its bytes can hold (a field takes at least three bytes),
so the read buffer's limit is what bounds it. A head with more fields than
an `http::HeaderMap` holds fails as too large (`try_reserve`,
`try_append`) instead of panicking. The 100 inline slots stay, so an
ordinary response allocates nothing more. A count set by the caller still
bounds the head. Trailers keep their count limit.

## content-length-values

`Client::decoder` refused a response head whose `Content-Length` values
differ, and one whose value is not a number, with one error,
`invalid content-length parsed`. RFC 9112 section 6.3 (item 5) makes both
invalid framing, and both stay errors; the patch gives differing numbers
their own error, `differing content-length values parsed`, with the
predicate `Error::is_parse_content_length_differ`. A list of identical
values is still accepted, as before.

## response-bytes

The HTTP/1 client reported a connection that ended, or failed to read or
write, before the response head was complete with the same error whether
or not part of a response had arrived: an end of stream after a partial
head was an incomplete message, as was one with no byte at all. RFC 9112
section 9.3.1 and RFC 9110 section 9.2.2 leave automatic retries to the
client, which needs to know whether the server had begun to answer. With
the patch, `Error::received_response_bytes` says whether any byte had
arrived for the head being read: part of the final head, an informational
(1xx) response, or empty lines before a head. `Buffered` records that a
read returned bytes while a head was parsed, cleared once a head is
complete; `Conn::on_read_head_error` sets it on a failed head read (before
the leading empty lines are dropped), and `Dispatcher::poll_catch` on every
other failure delivered in place of a response (a failed write, say). It is
false for every HTTP/2 error; for an error after the head (a body's) it has
no meaning. Nothing else changes: the error's kind, cause and message stay
as they were.

## Rebase procedure

1. A new wreq-proto release gets a new branch, `viper/wreq-proto-<version>`,
   from the commit its published crate names, with an equalizing commit if
   it was published from a modified checkout; the base verification above is
   repeated.
2. Each patch is applied again as its own commit, its markers kept, and
   dropped if upstream has an equivalent.
3. `cargo test -p wreq-proto` and the fork tests pass; this file gets the new
   `Base:`, `Branch:`, verification, ledger and a rebase-log line.
4. A Viper task moves the pin; Viper's gate step `wreq-fork` checks it.

## Rebase log

| Date | From | To | Conflicts | Effort |
| --- | --- | --- | --- | --- |
| none yet | | | | |

## Pin log

| Viper task | Commit | Change |
| --- | --- | --- |
| V16d-3a | `ebb0c589afdb82f559df4000e6e26052f7daeb7f` | the branch, the base and the patches `header-count-growth` and `content-length-values` |
| NET-RESEND-2 | the last commit of this range | the patch `response-bytes` |
