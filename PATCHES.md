# Viper's wreq fork: patch ledger of http2

This repository holds the Viper project's copies of the crates of its HTTP
stack, each on its own branch: `viper/wreq-0.16.1` carries
[wreq](https://github.com/0x676e67/wreq), `viper/wreq-proto-0.2.6` carries
[wreq-proto](https://github.com/0x676e67/wreq-proto) and
`viper/http2-0.5.20` (this branch) carries
[http2](https://github.com/0x676e67/http2), the HTTP/2 crate both build on.
Each `viper/*` branch carries a small set of generic patches on top of the
exact sources of a published release. Viper builds each crate from one
exact commit of its branch, through a Cargo `[patch.crates-io]` entry.

This file is the canonical ledger of this branch's patches. It holds the
verified base, one row and one section per patch, the rebase procedure and
the rebase and pin logs. Viper's own record of the fork (how the pins move,
the gate step that checks them, the cargo-deny source and the licence
obligations) is its ADR 0034, "The wreq fork".

Base: e7d8a70de1973f2d29b62e08c4d50f461e6c489a
Branch: viper/http2-0.5.20

## Rules

- **Branches.** One long-lived branch per crate and release,
  `viper/<crate>-<version>`. This branch starts at a root commit holding
  the exact tree of the commit the published crate names, without the
  upstream history (see "Base"). A `viper/*` branch is never force-pushed,
  and never deleted while any Viper revision pins a commit on it (a
  repository ruleset blocks both).
- **Markers.** Every changed hunk carries `VIPER-PATCH(<id>)` in a comment
  (`//` in Rust, `#` in TOML), with `<id>` matching `[a-z0-9-]+` and naming
  a row of the ledger below. The comment states the rule implemented or the
  problem fixed, with the specification where one exists. Every file that
  differs from the base, apart from this one, carries a marker. Viper's
  gate step `wreq-fork` fails when the marker ids in the pinned commit
  differ from the ledger ids, or when a changed file carries no marker.
- **Size.** Each patch is small (target at most 100 changed code lines) and
  self-contained, one commit per patch where possible.
- **Tests.** Every patch has tests in the fork (listed in its row) and a
  proof in Viper's gate: a named Viper test that must pass in the gate's
  run.
- **Upstream.** Each patch is generic and may be offered upstream; nothing
  goes to an upstream repository without the Viper owner's go-ahead for
  that specific draft. A patch is dropped when upstream releases an
  equivalent.
- **Licences.** http2 is MIT-licensed (`LICENSE`); patched files keep
  their notices, the licence file is unchanged, and each `VIPER-PATCH`
  marker records the change.
- **Commits** use the Viper owner's GitHub noreply identity.

## Base

The published crate names http2 commit
`5a9a1fe28154461318310e6044959c6dc8a60d17` (tag `v0.5.20`, "v0.5.20") of
`https://github.com/0x676e67/http2`, and was published from a clean
checkout. The branch does not carry that commit's history: GitHub's push
protection refuses it, because commits of 2017 in the history it shares
with hyperium/h2 hold a webhook URL in a `codecov.yml` that was deleted in
2018 and is not in the v0.5.20 tree. So the base is a root commit,
`e7d8a70de1973f2d29b62e08c4d50f461e6c489a`, whose tree is v0.5.20's own:
both have the git tree `c313ac421a4c858554e4043903b01b8ede295c31`
(`git rev-parse 'v0.5.20^{tree}'` in a clone of the upstream repository and
`git rev-parse 'e7d8a70d^{tree}'` here), so every file is upstream's, byte
for byte. The upstream commit stays the source of record. Verified on
2026-11-27:

| Crate | Published `.crate` SHA-256 (equals the crates.io index `cksum` and Viper's `Cargo.lock` checksum) | `.cargo_vcs_info.json` | Sources compared with the base |
| --- | --- | --- | --- |
| `http2` 0.5.20 | `92d3114be2f413b2e491e686b93a28cda30c355cffc8d091a57f8be4b1342896` | `sha1` `5a9a1fe28154461318310e6044959c6dc8a60d17`, not dirty, `path_in_vcs` empty | identical, byte for byte: the 67 packaged files that are not generated (`LICENSE`, `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, the 55 files under `src/`, the benches and examples), and `Cargo.toml.orig` equals the root `Cargo.toml`. Generated at packaging time and not compared: the normalized `Cargo.toml`, `Cargo.lock`, `.cargo_vcs_info.json` |

## Ledger

| Id | Reason | Register entry | Tests | Licence and upstream attribution | Upstream status |
| --- | --- | --- | --- | --- | --- |
| `h2-stream-priority` | each request's HEADERS frame carries its own RFC 9113 section 5.3.2 priority, chosen by the request's RFC 9218 urgency: a weight per urgency, an exclusive flag and a parent rule, in place of the one priority a connection gave every request | `adr:net-h2-priority-order` | fork: `tests/h2-tests/tests/viper_urgency_priorities.rs`; Viper: `viper-net::h2_priority urgency_priorities_set_each_headers_priority_and_parent` | MIT (Viper's own change) | candidate; never offered without the owner's approval |

## h2-stream-priority

http2 0.5.20 lets a client set one RFC 9113 section 5.3.2 priority, the
builder's `headers_stream_dependency`, which every request's HEADERS frame
carries, so a client could not tell a server which of its requests matter
more. With the patch a request may carry its RFC 9218 section 4.1 urgency,
`ext::Urgency` (0, the most urgent, to 7; 3 by default), in its
extensions, and `client::Builder::urgency_priorities` takes
`ext::UrgencyPriorities`: a weight for each urgency, whether the
dependency is exclusive, and the parent rule, `ext::UrgencyParent`:

- `Root`: every stream depends on stream 0;
- `NearestOpen`: a stream depends on the newest stream the connection
  opened, of those not closed, at the nearest urgency at or above its own
  (its own urgency first, then the next more urgent one), or on stream 0
  when there is none.

The connection keeps the streams it opened under `NearestOpen` with their
urgency, and drops those no longer stored or closed each time it opens
one. A request without an urgency takes the default one. Without the
option nothing changes: an urgency in a request's extensions is ignored,
and `headers_stream_dependency` applies as before. Stream ids, the order
of HEADERS frames and PRIORITY frames are unchanged.

## Rebase procedure

1. A new http2 release gets a new branch, `viper/http2-<version>`, from
   the commit its published crate names, with an equalizing commit if it
   was published from a modified checkout; the base verification above is
   repeated.
2. Each patch is applied again as its own commit, its markers kept, and
   dropped if upstream has an equivalent.
3. `cargo test -p h2-tests`, `cargo test --features unstable --lib` and
   the fork tests pass; this file gets the new `Base:`, `Branch:`,
   verification, ledger and a rebase-log line.
4. A Viper task moves the pin; Viper's gate step `wreq-fork` checks it.

## Rebase log

| Date | From | To | Conflicts | Effort |
| --- | --- | --- | --- | --- |
| none yet | | | | |

## Pin log

| Viper task | Commit | Change |
| --- | --- | --- |
| WREQ-FORK-4 | the last commit of this range | the branch, the base and the patch `h2-stream-priority` |
