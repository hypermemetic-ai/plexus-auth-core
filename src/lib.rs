//! Sealed-type primitives for the Plexus auth framework.
//!
//! This crate exists to host the Plexus authentication primitives —
//! `AuthContext`, `VerifiedUser`, `Principal`, and the forthcoming
//! `Credential<T>`, `Tenanted<S>`, `ForwardDerivation` — behind a crate
//! boundary that no consuming crate can bypass. The crate boundary, plus
//! Rust's orphan rules, plus crate-private constructors, escalate the
//! sealed-type defense from procedural (visibility within plexus-core) to
//! structural (visibility across crates).
//!
//! See `plans/AUTHZ/AUTHZ-0.md` §"Crate-level isolation amplifies the seal"
//! for the full rationale.
//!
//! # Public surface
//!
//! - [`AuthContext`] — the runtime auth value carried with every method
//!   invocation. The shape and current public API are preserved verbatim
//!   from `plexus-core`'s `plexus::auth` module to keep this migration
//!   mechanical; tightening the seal on `AuthContext::new` and field
//!   visibility is tracked as follow-up work (see
//!   `plans/AUTHZ/AUTHZ-CORE-CRATE-1-RUN-NOTES.md`).
//! - [`SessionValidator`] — the trait perimeter validators implement.
//! - [`VerifiedUser`] — sealed proof that an IdP-signed token was verified.
//! - [`Principal`] — sealed authenticated-actor identity (user, service, anon).
//! - [`BackendAuthCapabilities`] — capability-advertisement payload served
//!   at `_info` so generic clients can discover supported auth mechanisms
//!   (AUTHZ-CORE-3). Composed of [`AuthMechanism`] variants
//!   (`Bearer`, `Cookie`, `Oidc`, `Anonymous`) and the strong-typed
//!   primitives [`MethodPath`], [`IssuerUrl`], [`ClientId`],
//!   [`CookieName`], [`HeaderName`].
//!
//! # Sealing protections (per AUTHZ-0)
//!
//! `VerifiedUser` and `Principal` are introduced here with the strict seal
//! the AUTHZ-0 doc calls for:
//!
//! 1. **No fabrication.** Constructors are `pub(crate)` and callable only
//!    from inside `plexus-auth-core`. The trybuild test
//!    `tests/compile_fail/seal_*.rs` asserts this.
//! 2. **No backdoor `From`/`Into`.** Orphan rules forbid implementing
//!    foreign traits for foreign types from a third crate; only this crate
//!    can add such impls.
//! 3. **No accidental `Default`.** Explicitly NOT derived.
//! 4. **No leaky `Deserialize`.** Not derived for these types; raw JSON
//!    cannot fabricate a sealed value.
//! 5. **No mutation.** Fields are private; no setters; even with a sealed
//!    value in hand, no caller can mutate it.
//!
//! `AuthContext` retains its current public constructors (`new`,
//! `anonymous`) and `pub` fields for now, to preserve the public API that
//! callers across the workspace depend on. The crate boundary still gives
//! `AuthContext` the orphan-rule protection (no foreign `From`/`Into` from
//! third crates) and a single audit point for the type. Tightening the
//! `AuthContext` seal to match `VerifiedUser`/`Principal` is the next step
//! in the auth track and lands as a follow-up ticket.

pub mod auth;
pub mod capabilities;
pub mod principal;
pub mod verified_user;

pub use auth::{AuthContext, SessionValidator};
pub use capabilities::{
    AuthMechanism, BackendAuthCapabilities, BackendAuthCapabilitiesError, ClientId, ClientIdError,
    CookieName, CookieNameError, HeaderName, HeaderNameError, IssuerUrl, IssuerUrlError,
    MethodPath, MethodPathError,
};
pub use principal::{Principal, ServiceIdentity};
pub use verified_user::VerifiedUser;
