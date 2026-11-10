# Changelog

All notable changes to plexus-auth-core are documented here. This file starts
at 0.3.0; earlier changes are in the git history (tags `plexus-auth-core-v*`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2] — 2026-11-10

- `Gate::check_everywhere` (KEEL-31): a whole-service method is admitted only
  where its grant is held on `*`; a grant held on a narrower scope is refused
  as any other, typed, naming the scope. Additive.

## [0.3.1] — 2026-11-06

PLEXUS-45: the crate builds for `wasm32-unknown-unknown` (owner,
2026-11-06: "can we make plexus core wasm compatible without degrading
anything?"), with every native dependency unchanged.

### Changed

- **wasm32 only**, by target-specific dependency tables: jsonwebtoken 10 on
  its RustCrypto backend (ring, which 9 uses, needs clang for wasm32);
  getrandom 0.3 `wasm_js` and 0.2 `js`, uuid `js` and chrono `wasmbind`, so
  randomness and `Utc::now` come from the JS runtime rather than panicking.
  getrandom 0.3 also needs `--cfg getrandom_backend="wasm_js"` in the
  build's rustflags for the target. `src/oidc/` reads the same API from
  both jsonwebtoken majors; no source change.
- **Native: nothing.** jsonwebtoken stays 9 on ring; `cargo tree -e normal`
  for the host is the same as 0.3.0's, with and without features.
- The `adapters` feature stays native-only in practice (nostr's secp256k1
  is a C build).

Also in this release, merged after 0.3.0 — RETURNS-47: what a child needs to receive auth (owner, 2026-11-04).

### Added

- `Reach::nowhere()`: the reach of a call made for no one (a child under the
  `anonymous` forward policy, or one whose caller cannot be read): covers and
  allows nothing, and names no grant. No public constructor makes a reach
  that names a grant from a list of scopes: that is a gate's answer, and the
  child seam builds a hop's ceiling as a gate of the hop alone answers it.

### Changed

- A forward derivation that keeps the verified user but not the metadata
  (`identity_only`) keeps the caller's principal stamp: identity, not
  metadata. A `key:` or `nostr:` caller (no idp UUID in `user_id`) was named
  by no one in the callee (`principal()` answered `None`), so an
  `identity_only` child's `#[from_auth]` verifier refused it.

## [0.3.0]

Release with plexus-core 0.8.0 (BIDIR-6, BIDIR-17: a method's input half).

### Breaking

| Change | Before (0.2.2) | After | What to do |
|---|---|---|---|
| `duplex::CallCeiling` | `credit`, `max_items`, `max_bytes` | adds the public field `max_buffered`: the bytes one call may hold at once, past which the callee grants no more credit (never a refusal) | Name it in a struct literal, or use `..Default::default()` |
| `CallCeiling::default()` | `max_items` 1,000,000, `max_bytes` 64 MiB | `max_items` and `max_bytes` are `u64::MAX` (no lifetime limit unless a method opts in); `max_buffered` 64 MiB; `credit` 64 | Set `max_items` or `max_bytes` for a method that wants a lifetime limit |
| `duplex::DuplexRefusalCode` | eight variants | adds `OutOfSequence` (`out_of_sequence`) and `InvalidInput` (`invalid_input`) | Add them to an exhaustive match |

### Added

- `duplex::DEFAULT_INPUT_WINDOW` (64): the credit a method grants unless it
  says otherwise.
- `duplex::DEFAULT_MAX_BUFFERED` (64 MiB): the bytes one call may hold unless
  its method says otherwise.

### Changed

- `AuditRecord::duplex_refused` records `OutOfSequence` and `InvalidInput` as
  `AuditDenyReason::NotAccepted`.
