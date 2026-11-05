# Changelog

All notable changes to plexus-auth-core are documented here. This file starts
at 0.3.0; earlier changes are in the git history (tags `plexus-auth-core-v*`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

RETURNS-47: what a child needs to receive auth (owner, 2026-11-04).

### Added

- `Reach::from_hop_ceiling(grant, held_on)`: a child's reach for a call that
  came through the child seam (plexus-wire spec/12) — the near side's verdict
  as a ceiling. For the seam only: it is no gate's answer, and nothing else
  should make a reach from a list of scopes. It names `grant`
  (`Reach::grant`), covers exactly `held_on`, allows a target by name only
  when held on `*` (no gate behind it to resolve one), and `current` answers
  it unchanged.
- `Reach::nowhere()`: the reach of a call made for no one (a child under the
  `anonymous` forward policy): covers and allows nothing.

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
