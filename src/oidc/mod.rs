//! OIDC token validation — "the forthcoming verifier" (UT-1, UT-S01 D1).
//!
//! This module is the verifier that `verified_user.rs` was built to wait
//! for. It implements the UT-S01 resolution model: every plexus backend
//! validates tokens **locally, with zero shared secrets** —
//!
//! 1. Backend config names its trusted issuer URL and audience
//!    ([`OidcConfig`]).
//! 2. The validator fetches `{issuer}/.well-known/openid-configuration`
//!    (OIDC Discovery) and reads `jwks_uri`.
//! 3. It fetches the JWKS (RFC 7517), selects the key by the JWT header
//!    `kid`, and caches per the AUTH-8 policy (see "Caching policy").
//! 4. It validates the **RS256** signature plus the standard claims:
//!    `iss` (== configured issuer), `aud` (== configured audience),
//!    `exp`/`iat` (zero leeway — no grace), `sub` present.
//! 5. On success it mints the sealed
//!    [`VerifiedUser`](crate::VerifiedUser) — the only production call
//!    site of `VerifiedUser::new_sealed` — carrying the
//!    [`TenantId`](crate::TenantId) from the `org_id` claim (UT-S01 D3).
//!
//! # The Auth0-interchangeability bar (UT-S01 D2)
//!
//! The validator's only coupling to the IdP is (issuer URL, audience, the
//! five standard claims, `org_id`). Pointing [`OidcConfig`] at a real
//! Auth0 tenant (`https://<tenant>.auth0.com/`) with the backend
//! registered as an Auth0 API is a zero-code-change swap. The plexus
//! extensions `roles` / `username` are read if present and **optional for
//! validation**, per the bar's negative-space rule.
//!
//! # Caching policy (AUTH-8, adopted verbatim)
//!
//! | Condition | Behavior |
//! |---|---|
//! | JWKS fetch succeeds | cache keys; TTL = min(`Cache-Control: max-age`, 3600 s); default 3600 s |
//! | Token `kid` not in cache | exactly **one** unconditional refresh, then reject (`UnknownKeyId`) |
//! | IdP unreachable, cache present | keep validating with cached keys (degraded) — usable only for tokens whose `exp` is in the future, because `exp` is enforced with **zero grace** regardless |
//! | IdP unreachable, no cache | reject (`JwksUnavailable` / `Discovery`) |
//! | Degradation transitions | `auth_provider_degraded` / `auth_provider_restored` events under `target = "plexus::auth"` |
//!
//! # Algorithm posture
//!
//! RS256-only for now (maximum Auth0 / off-the-shelf-middleware
//! compatibility — UT-S01 open question 4). The design is
//! EdDSA-extensible: key admission lives in one match in
//! `jwks::admit_key`, and the per-token algorithm gate lives in one check
//! in `validator.rs` — adding `EdDSA` is one arm in each.
//!
//! # No-network testing
//!
//! [`JwksFetcher`] is the injection seam: tests supply a fixture fetcher
//! serving a canned discovery document and JWKS (see
//! `tests/oidc_validator.rs`). The production fetcher
//! (`ReqwestJwksFetcher`) is feature-gated behind `oidc-reqwest`.

pub mod config;
pub mod fetch;
pub(crate) mod jwks;
pub mod session;
pub mod validator;

pub use config::{Audience, AudienceError, OidcConfig};
pub use fetch::{FetchError, FetchedDocument, JwksFetcher};
#[cfg(feature = "oidc-reqwest")]
pub use fetch::ReqwestJwksFetcher;
pub use session::OidcSessionValidator;
pub use validator::{OidcError, OidcValidator, VerifiedToken};
