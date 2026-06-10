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
//! - [`Tenant`] — sealed unit of data isolation (AUTHZ-0 layer 4). The
//!   constructor is crate-private; the only path to a `Tenant` value is
//!   through the framework's [`TenantResolver`].
//! - [`TenantResolver`] — derives a `Tenant` from a verified
//!   `AuthContext`. Reference impls: [`ClaimTenantResolver`] (the 80%
//!   case) and [`SingleTenantResolver`] (explicit single-tenant
//!   opt-out).
//! - [`Credential`] — sealed framework-level credential primitive. The only
//!   path to a `Credential<T>` value is through [`CredentialMinter::mint`],
//!   itself reachable only by accepting a framework-injected reference. The
//!   custom `Serialize` impl emits a sentinel `{"$credential": "<id>"}` by
//!   default; the dispatch layer routes the inner value to a sidecar via an
//!   RAII guard while it builds the wire envelope (Tier B Q-WIRE-3).
//! - [`CredentialMinter`] — the injected service that mints credentials.
//! - [`CredentialMetadata`] — typed contract describing what the credential
//!   is and how to attach it on subsequent calls (kind, attach site, scheme,
//!   scopes, expiry, refresh/revoke hints, issuer, sensitivity).
//! - [`AuditRecord`] — the audit primitive consumed by AUTHZ default-deny
//!   dispatch (AUTHZ-CORE-5) and AUTHLANG-3's forwarding-policy path. Carries
//!   the principal chain, decision, reason, latency, and correlation ID for
//!   one scope check. [`AuditSink`] is the framework's persistence trait;
//!   [`TracingAuditSink`] is the default impl emitting `tracing::info!`
//!   events under `target = "plexus::audit"`.
//! - [`ScopeRegistry`] — hub-level roles→scopes source of truth (R-0,
//!   reviving AUTHZ-CORE-4 + CORE-6). [`Role`]s are named scope-sets with
//!   transitive, build-time-cycle-rejected inheritance; [`Scope`] gains the
//!   grammar-validated `try_new` and segment-bounded wildcard
//!   [`Scope::matches`]; [`RoleName`] gains `try_new`. The dispatch gate
//!   (R-5) computes `effective_scopes(AuthContext.roles)` and checks
//!   `Scope::matches(required)`.
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

/// Crate version, populated at compile time from `CARGO_PKG_VERSION`.
///
/// Exposed so the `plexus-rpc` umbrella can stamp it into the
/// `Capabilities` manifest backends embed in `_info`. See UMB-2.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod audit;
pub mod auth;
pub mod capabilities;
pub mod credential;
pub mod principal;
pub mod scope_registry;
pub mod tenant;
pub mod verified_user;

pub mod forward;

pub use audit::{
    AuditDecision, AuditDenyReason, AuditRecord, AuditRecordKind, AuditSink, ForwardPolicyApplied,
    RoleName, ScopeCheck, SensitiveField, SessionId, TracingAuditSink, UserId,
};
pub use auth::{AuthContext, SessionValidator};
pub use capabilities::{
    AuthMechanism, BackendAuthCapabilities, BackendAuthCapabilitiesError, ClientId, ClientIdError,
    CookieName, CookieNameError, HeaderName, HeaderNameError, IssuerUrl, IssuerUrlError,
    MethodPath, MethodPathError,
};
#[allow(deprecated)]
pub use credential::CredentialsRegistry;
pub use credential::{
    AttachmentSite, CapturedCredential, Credential, CredentialFieldMarker, CredentialId,
    CredentialIssuer, CredentialKind, CredentialKindName, CredentialMetadata, CredentialMinter,
    CredentialScheme, CredentialsRegistryFallback, CredentialsRegistryProbe, DispatchSidecar,
    HasCredentialMarkers, Origin, ParamName, Scope,
};
pub use forward::{
    Anonymous, CallSite, ForwardDerivation, ForwardPolicy, ForwardPolicyName, IdentityOnly,
    PassThrough, ANONYMOUS_NAME, IDENTITY_ONLY_NAME, PASS_THROUGH_NAME,
};
pub use principal::{Principal, ServiceIdentity};
pub use scope_registry::{
    Role, RoleNameError, ScopeError, ScopeRegistry, ScopeRegistryBuilder, ScopeRegistryError,
};
pub use tenant::{
    ClaimTenantResolver, Scoped, SingleTenantResolver, Tenant, TenantBoundary, TenantError,
    TenantResolver, TenantScopedStore, Tenanted,
};
pub use verified_user::VerifiedUser;
