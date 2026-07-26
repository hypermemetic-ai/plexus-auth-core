//! Namespaced identity and pluggable authentication (PLX-82 / M1·J).
//!
//! - [`Principal`] — an issuer-namespaced subject: `idp:<uuid>`,
//!   `nostr:<64-hex>`, `apikey:<id>`.
//! - [`Authenticator`] — one credential kind's verifier, producing an
//!   [`Authenticated`] proof from a [`Presentation`].
//! - [`CredentialLink`] — the store that lets one `Principal` hold many
//!   credentials.
//!
//! # THE `Principal` NAME COLLISION, AND HOW IT IS RESOLVED
//!
//! Three types were in play when this build started; PLX-82 resolves them
//! into **two concepts under one naming scheme**, distinguished by module
//! path — the same scheme `plexus-core` already uses.
//!
//! | Path | Concept | Question it answers |
//! |---|---|---|
//! | [`crate::principal::Principal`] (re-exported as `plexus_auth_core::Principal`, and as `plexus_core::plexus::Principal`) | **caller-stamp** — sealed `Anonymous \| User \| Service` | *What kind of actor* is on the other end of this call? |
//! | [`crate::identity::Principal`] (this module — deliberately **not** re-exported at the crate root) | **subject-name** — issuer-namespaced identifier | *Which* identity, and *who vouches* for it? |
//!
//! They are not competitors and neither replaces the other. They compose:
//! a caller-stamp of `Principal::User(..)` names an actor whose subject is an
//! `identity::Principal`, which is why
//! [`crate::principal::Principal::subject`] exists — the relationship is
//! expressed in code, not only in prose.
//!
//! ## Why not rename one of them?
//!
//! Renaming the caller-stamp would break `plexus_auth_core::Principal`,
//! `plexus_core::plexus::Principal`, `framework_stamped_principal`, and the
//! `derive_callee_context` signature across plexus-core, plexus-transport,
//! and plexus-macros — a workspace-wide break, on a name that is *correct*
//! for what it holds. Renaming the subject-name would diverge from the
//! `plexus_core::identity::Principal` that PLX-75 already landed and that
//! callers are already writing against. Neither name is wrong; only the
//! ambiguity was, and a module path removes it. There is no glob re-export
//! anywhere that could make them shadow one another.
//!
//! ## The third one: `plexus_core::identity::Principal`
//!
//! PLX-75 landed a subject-name type in `plexus-core`. This module's
//! [`Principal`] is a **deliberate mirror of it**, not a fork, and the
//! reason is a hard dependency fact PLX-82's contract did not account for:
//!
//! > `plexus-core` depends on `plexus-auth-core`. `plexus-auth-core` depends
//! > on no plexus crate at all — that is the entire point of the crate (see
//! > `Cargo.toml`'s header: it exists so the auth primitives sit behind a
//! > boundary nothing can bypass). [`AuthContext`](crate::AuthContext) lives
//! > here. It therefore **cannot** name `plexus_core::identity::Principal`
//! > without inverting the dependency arrow.
//!
//! So the type is defined here, at the bottom of the stack where
//! `AuthContext` can reach it, with the grammar, `Display`/`FromStr`
//! behavior, and wire form pinned byte-for-byte identical to PLX-75's. The
//! follow-up is mechanical and non-breaking: `plexus_core::identity` becomes
//! `pub use plexus_auth_core::identity::{Issuer, Principal, PrincipalParseError};`
//! and the duplicate implementation is deleted. Until then,
//! `plexus-idp/tests/principal_equivalence.rs` — which can see both crates —
//! asserts mechanically that the two agree on every accepted form, every
//! rejected form, and every serialization, so they cannot drift while the
//! duplication lasts.

mod authenticator;
mod linking;
mod principal;

pub use authenticator::{
    ApiKeyAuthenticator, ApiKeyDigest, Authenticated, AuthenticatorChain, AuthnRejection,
    Authenticator, BearerJwtAuthenticator, CookieAuthenticator, Presentation, TokenVerifier,
    VerifiedClaims,
};
pub use linking::{
    CredentialClass, CredentialLink, InMemoryCredentialLink, LinkError, LinkedCredential,
};
pub use principal::{Issuer, Principal, PrincipalParseError};
