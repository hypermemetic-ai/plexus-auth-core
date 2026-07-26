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
//! ## There is no third one: `plexus_core::identity::Principal` IS this type
//!
//! PLX-75 originally landed a subject-name type in `plexus-core`, before the
//! layering constraint was known:
//!
//! > `plexus-core` depends on `plexus-auth-core`. `plexus-auth-core` depends
//! > on no plexus crate at all — that is the entire point of the crate (see
//! > `Cargo.toml`'s header: it exists so the auth primitives sit behind a
//! > boundary nothing can bypass). [`AuthContext`](crate::AuthContext) lives
//! > here. It therefore **cannot** name `plexus_core::identity::Principal`
//! > without inverting the dependency arrow.
//!
//! PLX-82 worked around that with a byte-for-byte mirror here, kept in step
//! by an equivalence test in plexus-idp. **PLX-87 removed the duplication
//! rather than policing it**: this module is now the single definition, at
//! the bottom of the stack where `AuthContext` can reach it, and
//! `plexus_core::identity` is
//! `pub use plexus_auth_core::identity::{Issuer, Principal, PrincipalParseError};`.
//! The public path PLX-75 established keeps working and now names the same
//! type, so drift is not merely detected — it is unrepresentable. The
//! equivalence test was deleted along with the second definition it guarded;
//! its accepted/rejected corpus lives on in `principal.rs`'s unit tests.

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
