//! `Credential<T>`, `CredentialMinter`, and `CredentialMetadata` — sealed
//! framework-level credential primitive.
//!
//! Per `AUTHZ-CRED-CORE-1` and AUTHZ-0 principle 6 ("the user's safety property
//! is unforgeable"), a credential value is unforgeable from activation code.
//! The compiler enforces this: there is no public constructor for
//! [`Credential<T>`] reachable from outside `plexus-auth-core`, no public
//! mutator, no `Default`, no `Deserialize`. The only path to producing a
//! `Credential<T>` is via [`CredentialMinter::mint`], whose constructor is
//! itself `pub(crate)` — the framework's dispatch layer (`plexus-core` /
//! `plexus-transport`, in a follow-up ticket) is the only caller that can
//! obtain a minter, and activation code receives an immutable reference.
//!
//! # Sealing summary (per AUTHZ-0 §"Crate-level isolation amplifies the seal")
//!
//! | Protection           | Mechanism                                      |
//! |----------------------|------------------------------------------------|
//! | No fabrication       | `Credential::new_sealed` is `pub(crate)`       |
//! | No backdoor From/Into| Orphan rules forbid foreign-trait impls        |
//! | No accidental Default| Not derived                                    |
//! | No leaky Deserialize | Not derived; serialize-only round-trip         |
//! | No mutation          | Fields private; no `&mut` accessors            |
//! | No raw secret on wire| Custom `Serialize` emits a sentinel by default |
//!
//! # Sentinel-emitting serialization (Tier B Q-WIRE-3)
//!
//! `Credential<T>`'s `Serialize` impl emits, by default, a sentinel reference
//! of the shape `{"$credential": "<id>"}` rather than the inner value. The
//! framework's dispatch layer (per `AUTHZ-CRED-CORE-2`) flips a thread-local
//! toggle via an RAII guard for the duration of envelope-building; while the
//! toggle is set, the same `Serialize` impl additionally captures the value
//! into a dispatch-side sidecar (see `with_dispatch_capture` — crate-private,
//! reachable only inside `plexus-auth-core`). When the
//! toggle is unset (the default — any naive `serde_json::to_value(&payload)`
//! from application code, audit-log writers, or trace formatters), only the
//! sentinel is emitted; the inner value never appears in the produced JSON.
//!
//! The toggle's setter is `pub(crate)`. Activation code has no public path
//! to it. The guard's `Drop` impl clears the toggle even on panic so a
//! mid-serialization panic cannot leak the value.
//!
//! See `tests/compile_fail/credential_*.rs` for the structural enforcement
//! asserts.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Strong-typed newtypes (per the strong-typing skill).
//
// Every metadata field that would otherwise be a bare `String` is a newtype
// so the compiler catches accidental misuse. These mirror the names pinned
// by AUTHZ-S01-output §1 and CLIENTS-S01-output §1; when those upstream
// types land in shared crates this module's `pub use` aliases get retargeted
// (see ticket §"Risks" #3 — local-stub-now / refactor-on-fast-follow).
// ---------------------------------------------------------------------------

macro_rules! string_newtype {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            Serialize,
            Deserialize,
            JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wrap a string as a typed value.
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            /// Borrow the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume into the underlying string.
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_owned())
            }
        }
    };
}

// MethodPath, HeaderName, CookieName are re-exported from `crate::capabilities`
// (AUTHZ-CORE-3, which landed first). The wire-validated `try_new` constructors
// live there.
pub use crate::capabilities::{CookieName, HeaderName, MethodPath};

string_newtype! {
    /// Atomic capability identifier, e.g. `cone.send_message`. Local stub
    /// for the canonical `Scope` newtype pinned by AUTHZ-S01-output §1.
    Scope
}

string_newtype! {
    /// Backend Origin identifier (typically a URL like `ws://localhost:4444`).
    /// Local stub for the canonical `Origin` newtype pinned by
    /// CLIENTS-S01-output §1. NOTE: the workspace also has an unrelated
    /// `plexus_core::types::Origin` (plugin-id + method, not URL-shaped); the
    /// AUTHZ-CRED design uses the URL-shaped Origin from CLIENTS-S01.
    Origin
}

string_newtype! {
    /// Credential attach-time prefix, e.g. `"Bearer "` (trailing space
    /// included). Pinned by AUTHZ-CRED-S01-output §2.
    CredentialScheme
}

string_newtype! {
    /// Opaque kind name for `CredentialKind::Other`. The framework's
    /// compatibility logic treats `Other`-kinded credentials as untagged for
    /// the purposes of `requires_credential` matching (per Tier B Q-FLOW-2).
    CredentialKindName
}

string_newtype! {
    /// Parameter name for in-RPC-parameter and first-frame attachment sites.
    ParamName
}

string_newtype! {
    /// Per-response credential identifier (the `<id>` in the
    /// `{"$credential": "<id>"}` sentinel). Generated by the framework's
    /// dispatch layer at envelope-build time; opaque to activations.
    CredentialId
}

// ---------------------------------------------------------------------------
// CredentialKind — closed enum (Tier B Q-FLOW-2).
// ---------------------------------------------------------------------------

/// What kind of credential this is. Tags storage decisions and drives the
/// selection filter (`AUTHZ-CRED-CLI-3`). **Closed** for v1 — third crates
/// cannot extend the enum; backends with bespoke schemes use the
/// [`CredentialKind::Other`] escape valve.
///
/// The cost of going `Other` is loss of generic client integration — a method
/// requiring `Bearer` will not auto-attach an `Other`-kinded credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialKind {
    /// Static or short-lived bearer token (JWT, opaque token).
    Bearer,
    /// Cookie-shaped session credential (server may issue `Set-Cookie`).
    Cookie,
    /// OAuth/OIDC access token (paired with refresh; `refresh_via` populated).
    OauthAccess,
    /// OAuth/OIDC refresh token. Long-lived, used to mint new
    /// [`CredentialKind::OauthAccess`] credentials.
    OauthRefresh,
    /// OIDC ID token (informational identity assertion; not for auth).
    OidcId,
    /// AWS STS credential set (composite: access_key_id + secret + token + exp).
    AwsSts,
    /// Macaroon-style capability token with caveats.
    Macaroon,
    /// Custom kind, for backends with bespoke schemes; stored opaquely.
    Other {
        /// Opaque name supplied by the backend.
        name: CredentialKindName,
    },
}

// ---------------------------------------------------------------------------
// AttachmentSite — closed enum.
// ---------------------------------------------------------------------------

/// Where the credential is attached on the wire when sent on subsequent
/// calls. The framework's client-side replay machinery reads this to build
/// the outbound request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "site", rename_all = "snake_case")]
pub enum AttachmentSite {
    /// HTTP header. e.g. `Authorization: <scheme><value>`.
    Header {
        /// The header name (e.g. `authorization`).
        name: HeaderName,
    },
    /// HTTP cookie. e.g. `Cookie: plexus_session=<value>`.
    Cookie {
        /// The cookie name (e.g. `plexus_session`).
        name: CookieName,
    },
    /// First-frame WS auth: included as a parameter to a setup method.
    FirstFrame {
        /// The method that the client calls first on the WS connection.
        setup_method: MethodPath,
        /// The parameter on that setup call where the credential is passed.
        param: ParamName,
    },
    /// In-RPC parameter: each call receives this credential as a named
    /// parameter on the inbound activation. Used for backends without HTTP
    /// cookie/header support (e.g., pure stdio).
    InRpcParam {
        /// The parameter name on every credential-requiring method.
        param: ParamName,
    },
}

// ---------------------------------------------------------------------------
// CredentialIssuer.
// ---------------------------------------------------------------------------

/// Identity of the issuing party: the Origin the credential was issued from
/// and the method that issued it. Drives the named-session auto-naming
/// algorithm (AUTHZ-CRED-S01-output §5) and ties the credential to its
/// lineage in audit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CredentialIssuer {
    /// Backend Origin that issued this credential.
    pub origin: Origin,
    /// Method whose return type carries this credential field.
    pub method: MethodPath,
}

impl CredentialIssuer {
    /// Construct a `CredentialIssuer` value. Public — the issuer is not a
    /// secret; activation code may construct one to pass into mint (the
    /// `Credential<T>` itself remains sealed).
    pub fn new(origin: Origin, method: MethodPath) -> Self {
        Self { origin, method }
    }
}

// ---------------------------------------------------------------------------
// CredentialMetadata — the framework's contract surface.
// ---------------------------------------------------------------------------

/// What this credential is and how to attach it on subsequent calls.
///
/// Every metadata field is a typed newtype, never a bare string. The
/// [`CredentialMetadata::sensitive`] field is always `true`; it exists on the
/// struct so the metadata is the single source of truth for the redaction
/// pipeline (AUTHZ-PRIVACY-1).
///
/// Metadata is **fixed at mint time**: a `Credential<T>` exposes its metadata
/// via [`Credential::metadata`], but there is no mutable accessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CredentialMetadata {
    /// What kind of credential this is. Tags storage decisions and drives
    /// selection.
    pub kind: CredentialKind,

    /// Where the credential is attached on the wire when sent on subsequent
    /// calls.
    pub attach_as: AttachmentSite,

    /// Optional prefix prepended to the value at attach time (e.g.,
    /// `"Bearer "` for `Authorization: Bearer <token>`). Stored in the
    /// metadata so the client doesn't have to guess.
    pub scheme: Option<CredentialScheme>,

    /// Which scopes this credential authorizes. Empty set means "scope
    /// decision is server-side; client doesn't filter."
    pub scopes: Vec<Scope>,

    /// Hard expiry of the credential value, if known at issue time. Used
    /// for proactive refresh and for dropping stale stored credentials.
    pub expires_at: Option<DateTime<Utc>>,

    /// Optional refresh hint: if this credential expires, call this method
    /// to obtain a fresh one. The named-session framework handles the swap;
    /// activation code is uninvolved.
    pub refresh_via: Option<MethodPath>,

    /// Optional revocation hint: calling this method invalidates the
    /// credential server-side.
    pub revoke_via: Option<MethodPath>,

    /// Identity of the issuing party.
    pub issuer: CredentialIssuer,

    /// Sensitivity marker for the redaction pipeline (AUTHZ-PRIVACY-1).
    /// Always `true`; present for type-system uniformity so any code that
    /// reads the metadata has a single source of truth.
    pub sensitive: bool,
}

impl CredentialMetadata {
    /// Construct a fresh `CredentialMetadata`. The `sensitive` flag is always
    /// initialized to `true`; the field exists so callers reading metadata
    /// can treat it as the single source of truth without consulting outside
    /// state.
    ///
    /// Public — the metadata is not a secret. The seal is on the credential
    /// VALUE, not on the metadata that describes it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: CredentialKind,
        attach_as: AttachmentSite,
        scheme: Option<CredentialScheme>,
        scopes: Vec<Scope>,
        expires_at: Option<DateTime<Utc>>,
        refresh_via: Option<MethodPath>,
        revoke_via: Option<MethodPath>,
        issuer: CredentialIssuer,
    ) -> Self {
        Self {
            kind,
            attach_as,
            scheme,
            scopes,
            expires_at,
            refresh_via,
            revoke_via,
            issuer,
            sensitive: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Credential<T> — the sealed wrapper.
// ---------------------------------------------------------------------------

/// A sealed credential value. The inner `T` is constructable only via a
/// [`CredentialMinter`] — itself only obtainable as a function parameter
/// injected by the framework into credential-issuing methods.
///
/// Activation code can:
///   - Construct via `minter.mint(payload, metadata)` (the framework witnesses
///     the construction)
///   - Read metadata via [`Credential::metadata`] (immutable reference)
///   - Serialize via `serde_json::to_value(&cred)` — this produces ONLY the
///     sentinel `{"$credential": "<id>"}`; the inner value never appears.
///
/// Activation code CANNOT:
///   - Construct from raw bytes (no public `new` / `From<T>`)
///   - Mutate the inner value (no `&mut` accessor)
///   - Read the inner value via `serde_json::to_value` (the custom `Serialize`
///     impl writes the sentinel, not the value)
///   - Deserialize from raw JSON (`Deserialize` is intentionally absent)
///
/// # Sealing
///
/// `Credential<T>::new_sealed` is `pub(crate)`. Only [`CredentialMinter`]
/// inside this crate calls it. The compile-fail tests in
/// `tests/compile_fail/credential_*.rs` assert that external construction
/// is rejected.
#[derive(Debug, Clone)]
pub struct Credential<T> {
    /// The inner credential value. Private — the only public accessor is
    /// the custom `Serialize` impl, which writes the sentinel by default
    /// and routes the value into the sidecar only when the dispatch-side
    /// capture toggle is active.
    inner: T,

    /// The metadata fixed at mint time.
    metadata: CredentialMetadata,

    /// Stable per-credential id used in the `{"$credential": "<id>"}`
    /// sentinel. Generated at mint time; opaque to activations.
    id: CredentialId,
}

impl<T> Credential<T> {
    /// Mint a new `Credential<T>`. Crate-private — only [`CredentialMinter`]
    /// inside `plexus-auth-core` calls this. External crates cannot reach it
    /// (compile-fail tests assert this).
    pub(crate) fn new_sealed(inner: T, metadata: CredentialMetadata, id: CredentialId) -> Self {
        Self {
            inner,
            metadata,
            id,
        }
    }

    /// Immutable accessor for the metadata. There is no mutable counterpart —
    /// metadata is fixed at mint time.
    pub fn metadata(&self) -> &CredentialMetadata {
        &self.metadata
    }

    /// The credential's stable id (used in the wire sentinel).
    pub fn id(&self) -> &CredentialId {
        &self.id
    }

    /// Framework-internal accessor for the inner value. `pub(crate)` to
    /// `plexus-auth-core` so the dispatch-bridge code inside this crate can
    /// extract the value for sidecar emission. Activation code has no
    /// public path to this method.
    ///
    /// Per ticket §"Risks" #2, the cross-crate accessor for the dispatch
    /// layer in plexus-core will be added as a follow-up via a sealed marker
    /// trait the dispatch crate implements; this `pub(crate)` accessor is
    /// the first step.
    ///
    /// `dead_code` is allowed because the dispatch-layer caller lands in
    /// `AUTHZ-CRED-CORE-2`; the accessor is exercised by this crate's unit
    /// tests but has no production consumer until then.
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &T {
        &self.inner
    }
}

// `Default` is intentionally NOT derived. A default credential would be an
// unsigned, anonymously-minted value with no metadata — a security footgun.
// Compile-fail test `tests/compile_fail/credential_no_default.rs` asserts.

// `Deserialize` is intentionally NOT derived. Raw JSON must never fabricate
// a sealed credential value; the only path to one is `CredentialMinter::mint`.

// ---------------------------------------------------------------------------
// Audit-side projection.
// ---------------------------------------------------------------------------

impl<T> Credential<T> {
    /// Project to the metadata for audit-record emission. Read-only; the
    /// returned reference is the metadata exactly as fixed at mint time.
    ///
    /// Equivalent to [`Self::metadata`], named separately to make the
    /// audit-side projection grep-discoverable. Per
    /// AUTHZ-CRED-S01-output §8, the audit pipeline records
    /// `credentials_issued: Vec<CredentialMetadata>` — this is the projection
    /// that produces it. The inner credential value is never included.
    pub fn audit_projection(&self) -> &CredentialMetadata {
        &self.metadata
    }
}

// ---------------------------------------------------------------------------
// Sentinel-emitting Serialize impl (Tier B Q-WIRE-3).
// ---------------------------------------------------------------------------

/// The shape of a credential captured into the dispatch-side sidecar.
///
/// `value` holds the JSON-encoded inner credential payload; `metadata` rides
/// alongside. Only emitted into the sidecar when the dispatch capture toggle
/// is active; otherwise the credential's `Serialize` impl emits only the
/// sentinel.
#[derive(Debug)]
pub struct CapturedCredential {
    /// JSON-encoded inner value. Stored as `serde_json::Value` so the
    /// dispatch wrapper can re-emit it in the envelope without re-serializing
    /// the typed value through a second pass.
    pub value: serde_json::Value,
    /// The metadata as fixed at mint time.
    pub metadata: CredentialMetadata,
}

/// Sidecar collector populated by the credential `Serialize` impl while a
/// [`DispatchCaptureGuard`] is active. The dispatch layer reads the
/// collected map after serialization completes and emits it as the
/// `_credentials` envelope key (AUTHZ-CRED-S01-output §3, Q-WIRE-1).
#[derive(Debug, Default)]
pub struct DispatchSidecar {
    /// Map of credential id → captured value+metadata.
    map: HashMap<CredentialId, CapturedCredential>,
}

impl DispatchSidecar {
    /// Construct an empty sidecar.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain the collected entries. The dispatch layer calls this after the
    /// outer `Serialize` pass completes.
    pub fn drain(&mut self) -> HashMap<CredentialId, CapturedCredential> {
        std::mem::take(&mut self.map)
    }

    /// Whether the sidecar has captured any credential during the active
    /// dispatch pass.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Number of captured credentials.
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

thread_local! {
    /// While `Some(sidecar)`, the credential `Serialize` impl writes the
    /// inner value into the sidecar AND emits the sentinel inline. While
    /// `None` (the default — application code, audit writers, naive
    /// `serde_json::to_value` calls), only the sentinel is emitted; the
    /// value never appears in the produced JSON.
    ///
    /// There is no public setter for activation code. The only path to
    /// install a sidecar is via [`DispatchCaptureGuard::install`], whose
    /// constructor is `pub(crate)` and reachable only from the
    /// dispatch-bridge code in this crate.
    static DISPATCH_SIDECAR: RefCell<Option<DispatchSidecar>> = const { RefCell::new(None) };
}

/// Counter for auto-generated credential ids. The framework's dispatch
/// layer is the only caller; activations never see this directly.
static CREDENTIAL_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_credential_id() -> CredentialId {
    let n = CREDENTIAL_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    CredentialId::new(format!("cred_{n}"))
}

/// RAII guard that activates dispatch-side capture for the lifetime of the
/// guard. The constructor is `pub(crate)`: activation code cannot create
/// one. The dispatch layer (`plexus-core` / `plexus-transport`, via a
/// `pub(crate)`-exposed helper in this crate) is the only caller.
///
/// On `Drop`, the guard clears the thread-local even if the wrapped
/// operation panicked, so a mid-serialization panic cannot leak the value
/// onto a subsequent reentrant call.
pub struct DispatchCaptureGuard {
    /// The previous sidecar (if any) is restored on drop, supporting nested
    /// dispatch passes (rare but well-defined).
    previous: Option<DispatchSidecar>,
}

impl DispatchCaptureGuard {
    /// Install a fresh sidecar for the lifetime of the returned guard.
    /// `pub(crate)` — activation code has no path to construct one.
    ///
    /// `dead_code` is allowed because the dispatch-layer caller lands in
    /// `AUTHZ-CRED-CORE-2`; the guard must exist now so the compile-fail
    /// tests can assert external code cannot reach it.
    #[allow(dead_code)]
    pub(crate) fn install() -> Self {
        let previous = DISPATCH_SIDECAR.with(|cell| {
            let prev = cell.borrow_mut().take();
            *cell.borrow_mut() = Some(DispatchSidecar::new());
            prev
        });
        Self { previous }
    }

    /// Drain the captured credentials from the active sidecar. Returns
    /// `None` if (unexpectedly) no sidecar is installed. `pub(crate)` for
    /// the same reason as [`Self::install`].
    #[allow(dead_code)]
    pub(crate) fn drain(&self) -> Option<HashMap<CredentialId, CapturedCredential>> {
        DISPATCH_SIDECAR.with(|cell| cell.borrow_mut().as_mut().map(|s| s.drain()))
    }
}

impl Drop for DispatchCaptureGuard {
    fn drop(&mut self) {
        // Restore the previous sidecar (or clear). Done unconditionally so a
        // panic mid-serialization cannot leave the toggle dangling.
        let prev = self.previous.take();
        DISPATCH_SIDECAR.with(|cell| {
            *cell.borrow_mut() = prev;
        });
    }
}

/// Convenience helper: run `f` with a fresh dispatch sidecar installed, then
/// return both `f`'s output and the captured credentials.
///
/// `pub(crate)` — same reason as [`DispatchCaptureGuard`].
///
/// # Panic-safety
///
/// If `f` panics, the guard's `Drop` impl clears the thread-local before
/// the panic unwinds past this function, so a subsequent reentrant call
/// observes a clean state. See the unit test
/// `dispatch_capture_resets_on_panic` for the assertion.
#[allow(dead_code)]
pub(crate) fn with_dispatch_capture<F, R>(f: F) -> (R, HashMap<CredentialId, CapturedCredential>)
where
    F: FnOnce() -> R,
{
    let guard = DispatchCaptureGuard::install();
    let out = f();
    let captured = guard.drain().unwrap_or_default();
    drop(guard);
    (out, captured)
}

impl<T> Serialize for Credential<T>
where
    T: Serialize,
{
    /// Emits the sentinel `{"$credential": "<id>"}` always.
    ///
    /// If a dispatch-capture guard is active on the current thread, the
    /// inner value is ALSO captured into the sidecar (keyed by id) so the
    /// dispatch wrapper can emit it under the envelope's `_credentials`
    /// key. Application code that calls `serde_json::to_value(&credential)`
    /// without a guard sees only the sentinel — the inner value never
    /// appears in the produced JSON.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Capture into the sidecar if active. We do this BEFORE writing the
        // sentinel so a serialization failure mid-write does not leave a
        // half-captured value visible to the dispatch wrapper.
        //
        // Serializing the inner value to a `serde_json::Value` here is a
        // necessary step because the outer Serializer may not be JSON
        // (e.g., bincode used by an audit sink, MessagePack); the sidecar
        // is JSON-only by design (the envelope is JSON-RPC), so we lift
        // the inner value to JSON for sidecar storage regardless of the
        // outer serializer's target format.
        DISPATCH_SIDECAR.with(|cell| {
            let mut borrow = cell.borrow_mut();
            if let Some(sidecar) = borrow.as_mut() {
                // Failure to JSON-serialize the inner value is non-fatal for
                // the sentinel emission — the dispatch wrapper sees the
                // missing entry and surfaces a structured error later. We
                // store a `null` placeholder so the id is reserved even on
                // serialization failure (rare; T is constrained Serialize).
                let value = serde_json::to_value(&self.inner).unwrap_or(serde_json::Value::Null);
                sidecar.map.insert(
                    self.id.clone(),
                    CapturedCredential {
                        value,
                        metadata: self.metadata.clone(),
                    },
                );
            }
        });

        // Emit the sentinel. Always — whether or not a guard is active, the
        // outer JSON document contains only `{"$credential": "<id>"}` where
        // the credential lived. The inner value never inlines here.
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("$credential", self.id.as_str())?;
        map.end()
    }
}

// ---------------------------------------------------------------------------
// CredentialMinter — the framework's injected service.
// ---------------------------------------------------------------------------

/// The framework-issued service that mints sealed [`Credential<T>`] values.
///
/// `CredentialMinter`'s constructor is `pub(crate)` — only `plexus-auth-core`
/// can produce one. The framework's dispatch layer (per `AUTHZ-CRED-CORE-2`)
/// injects a `&CredentialMinter` into credential-issuing methods; activation
/// code receives the reference but cannot construct its own minter, nor
/// extend the seal by aliasing the type.
///
/// The minter ties construction to the originating method invocation so
/// audit can attribute the issuance. v1 carries the issuer hint as a stored
/// field on the minter so [`CredentialMinter::mint_with_issuer`] does not
/// require it as a separate argument; richer audit context (call id,
/// invocation chain position) is added in `AUTHZ-CRED-CORE-2` when the
/// dispatch-layer wiring lands.
#[derive(Debug, Clone)]
pub struct CredentialMinter {
    /// The issuer that subsequent mints stamp onto every credential's
    /// metadata when [`CredentialMinter::mint_with_issuer`] is used (the
    /// variant that takes pre-built metadata bypasses this field).
    default_issuer: CredentialIssuer,
}

impl CredentialMinter {
    /// Construct a minter scoped to a particular issuer. Crate-private —
    /// only the framework's dispatch layer (in a follow-up ticket) calls
    /// this; activation code receives a reference, never constructs one.
    ///
    /// `dead_code` is allowed because the dispatch-layer caller lands in
    /// `AUTHZ-CRED-CORE-2`. The constructor must exist now so the
    /// compile-fail tests have something to point at.
    #[allow(dead_code)]
    pub(crate) fn new_sealed(default_issuer: CredentialIssuer) -> Self {
        Self { default_issuer }
    }

    /// The default issuer the minter stamps onto credentials minted via
    /// [`CredentialMinter::mint_with_issuer`]. Useful for audit hooks.
    pub fn issuer(&self) -> &CredentialIssuer {
        &self.default_issuer
    }

    /// Mint a sealed [`Credential<T>`] from a raw payload and pre-built
    /// metadata.
    ///
    /// This is the **only** public path from a raw `T` to a sealed
    /// `Credential<T>`. Activation code calls it via the framework-injected
    /// `&CredentialMinter` reference.
    pub fn mint<T>(&self, payload: T, metadata: CredentialMetadata) -> Credential<T> {
        let id = next_credential_id();
        Credential::new_sealed(payload, metadata, id)
    }

    /// Mint a sealed [`Credential<T>`] from a raw payload, populating the
    /// metadata's `issuer` field from the minter's [`Self::issuer`]. The
    /// caller supplies everything else.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_with_issuer<T>(
        &self,
        payload: T,
        kind: CredentialKind,
        attach_as: AttachmentSite,
        scheme: Option<CredentialScheme>,
        scopes: Vec<Scope>,
        expires_at: Option<DateTime<Utc>>,
        refresh_via: Option<MethodPath>,
        revoke_via: Option<MethodPath>,
    ) -> Credential<T> {
        let metadata = CredentialMetadata::new(
            kind,
            attach_as,
            scheme,
            scopes,
            expires_at,
            refresh_via,
            revoke_via,
            self.default_issuer.clone(),
        );
        self.mint(payload, metadata)
    }
}

// ---------------------------------------------------------------------------
// Unit tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_issuer() -> CredentialIssuer {
        CredentialIssuer::new(
            Origin::new("ws://localhost:4444"),
            MethodPath::try_new("auth.login").unwrap(),
        )
    }

    fn sample_metadata() -> CredentialMetadata {
        CredentialMetadata::new(
            CredentialKind::Bearer,
            AttachmentSite::Header {
                name: HeaderName::try_new("authorization").unwrap(),
            },
            Some(CredentialScheme::new("Bearer ")),
            vec![Scope::new("cone.send_message")],
            None,
            Some(MethodPath::try_new("auth.refresh").unwrap()),
            Some(MethodPath::try_new("auth.logout").unwrap()),
            sample_issuer(),
        )
    }

    #[test]
    fn minter_mints_credential_via_internal_api() {
        // Acceptance criterion 2 + the ticket's "CredentialMinter mints
        // successfully via internal API" test.
        let minter = CredentialMinter::new_sealed(sample_issuer());
        let cred: Credential<String> =
            minter.mint("eyJhbGciOiJIUzI1NiIs...token".to_string(), sample_metadata());
        // The credential carries the metadata verbatim.
        assert_eq!(cred.metadata().kind, CredentialKind::Bearer);
        // The audit projection equals the metadata.
        assert_eq!(cred.audit_projection(), cred.metadata());
        // The inner accessor is reachable from inside the crate (this test
        // lives inside `plexus-auth-core`).
        assert_eq!(cred.inner(), "eyJhbGciOiJIUzI1NiIs...token");
    }

    #[test]
    fn metadata_sensitive_is_always_true() {
        let m = sample_metadata();
        assert!(m.sensitive, "sensitive must be initialized to true");
    }

    #[test]
    fn credential_id_is_unique_per_mint() {
        let minter = CredentialMinter::new_sealed(sample_issuer());
        let c1: Credential<String> = minter.mint("a".to_string(), sample_metadata());
        let c2: Credential<String> = minter.mint("b".to_string(), sample_metadata());
        assert_ne!(c1.id(), c2.id());
    }

    #[test]
    fn serialize_outside_dispatch_emits_only_sentinel() {
        // Acceptance criterion 9: serde_json::to_value(&credential) outside
        // dispatch context produces an object containing the $credential
        // sentinel and NO inner value.
        let minter = CredentialMinter::new_sealed(sample_issuer());
        let cred: Credential<String> =
            minter.mint("super-secret-token".to_string(), sample_metadata());
        let v = serde_json::to_value(&cred).expect("serialize");
        // The serialized form is exactly `{"$credential": "<id>"}`.
        let obj = v.as_object().expect("object");
        assert_eq!(obj.len(), 1, "sentinel is the only key");
        let id = obj
            .get("$credential")
            .and_then(|v| v.as_str())
            .expect("$credential id is a string");
        assert_eq!(id, cred.id().as_str());
        // The inner value never appears in the serialized form.
        let serialized = serde_json::to_string(&cred).expect("string");
        assert!(
            !serialized.contains("super-secret-token"),
            "inner value must not appear in default serialization, got: {serialized}"
        );
    }

    #[test]
    fn serialize_inside_dispatch_captures_value_into_sidecar() {
        // Acceptance criterion 10: when the dispatch-side thread-local is
        // active under a scoped guard, the inner value is captured into a
        // sidecar AND the sentinel is emitted inline. When inactive, only
        // the sentinel is emitted.
        let minter = CredentialMinter::new_sealed(sample_issuer());
        let cred: Credential<String> =
            minter.mint("dispatch-secret".to_string(), sample_metadata());

        let (json_value, captured) = with_dispatch_capture(|| {
            serde_json::to_value(&cred).expect("serialize under guard")
        });

        // The outer JSON still contains only the sentinel.
        let obj = json_value.as_object().expect("object");
        assert!(obj.contains_key("$credential"));
        assert!(!obj.contains_key("inner"));

        // The sidecar captured the inner value keyed by id.
        assert_eq!(captured.len(), 1);
        let entry = captured.get(cred.id()).expect("captured by id");
        assert_eq!(
            entry.value,
            serde_json::Value::String("dispatch-secret".into())
        );
        assert_eq!(entry.metadata.kind, CredentialKind::Bearer);

        // After the guard drops, a subsequent serialization is back to
        // sentinel-only (no value capture).
        let plain = serde_json::to_value(&cred).expect("serialize after guard");
        assert!(plain
            .as_object()
            .expect("object")
            .contains_key("$credential"));
        // And the inner value does not appear in the plain serialization.
        let plain_str = serde_json::to_string(&plain).unwrap();
        assert!(!plain_str.contains("dispatch-secret"));
    }

    #[test]
    fn dispatch_capture_resets_on_panic() {
        // Acceptance criterion 11: the toggle's guard is reset on drop even
        // when the wrapped operation panics. A subsequent serialization
        // must see a clean state (no leaking into a stale sidecar).
        let minter = CredentialMinter::new_sealed(sample_issuer());
        let cred: Credential<String> =
            minter.mint("panic-time-secret".to_string(), sample_metadata());

        // Run a closure that installs the guard then panics. We use
        // catch_unwind so the test framework doesn't abort.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = DispatchCaptureGuard::install();
            // Confirm capture is active.
            DISPATCH_SIDECAR.with(|cell| {
                assert!(cell.borrow().is_some(), "sidecar installed");
            });
            panic!("simulated panic mid-serialization");
        }));

        // After the panic, the thread-local must be clean.
        DISPATCH_SIDECAR.with(|cell| {
            assert!(
                cell.borrow().is_none(),
                "sidecar must be cleared on panic — got Some"
            );
        });

        // And a subsequent default serialization still emits the sentinel.
        let v = serde_json::to_value(&cred).expect("serialize after panic");
        let obj = v.as_object().expect("object");
        assert!(obj.contains_key("$credential"));
        // No stray value capture from a leaked sidecar.
        assert!(!serde_json::to_string(&v)
            .unwrap()
            .contains("panic-time-secret"));
    }

    #[test]
    fn audit_projection_yields_metadata_only() {
        // Acceptance criterion 12: the audit projection produces only the
        // metadata; the inner value never appears in audit output.
        let minter = CredentialMinter::new_sealed(sample_issuer());
        let cred: Credential<String> =
            minter.mint("audit-secret".to_string(), sample_metadata());
        let projection: &CredentialMetadata = cred.audit_projection();
        // The projection is metadata-equivalent...
        let audit_json = serde_json::to_string(projection).expect("audit serialize");
        // ...and does not contain the inner value.
        assert!(
            !audit_json.contains("audit-secret"),
            "audit projection must not include inner value, got: {audit_json}"
        );
        // It does include the metadata's `kind`.
        assert!(audit_json.contains("\"kind\""));
    }

    #[test]
    fn metadata_serialization_round_trips() {
        // The ticket's third explicit test in the Acceptance gate: metadata
        // serialization round-trips.
        let original = sample_metadata();
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: CredentialMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
    }

    #[test]
    fn metadata_round_trips_with_oauth_other_variant() {
        // Tier B Q-FLOW-2: the `Other { name }` escape valve round-trips.
        let mut m = sample_metadata();
        m.kind = CredentialKind::Other {
            name: CredentialKindName::new("trak.custom"),
        };
        let json = serde_json::to_string(&m).expect("serialize");
        let parsed: CredentialMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, m);
    }

    #[test]
    fn attachment_site_variants_round_trip() {
        // Each AttachmentSite variant serializes and deserializes cleanly.
        let variants = vec![
            AttachmentSite::Header {
                name: HeaderName::try_new("authorization").unwrap(),
            },
            AttachmentSite::Cookie {
                name: CookieName::try_new("plexus_session").unwrap(),
            },
            AttachmentSite::FirstFrame {
                setup_method: MethodPath::try_new("auth.connect").unwrap(),
                param: ParamName::new("token"),
            },
            AttachmentSite::InRpcParam {
                param: ParamName::new("session_token"),
            },
        ];
        for site in variants {
            let json = serde_json::to_string(&site).expect("serialize");
            let parsed: AttachmentSite = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, site);
        }
    }

    #[test]
    fn credential_kind_round_trips_all_variants() {
        // The closed enum has 8 variants; each serializes and deserializes.
        let variants = vec![
            CredentialKind::Bearer,
            CredentialKind::Cookie,
            CredentialKind::OauthAccess,
            CredentialKind::OauthRefresh,
            CredentialKind::OidcId,
            CredentialKind::AwsSts,
            CredentialKind::Macaroon,
            CredentialKind::Other {
                name: CredentialKindName::new("custom_scheme"),
            },
        ];
        for k in variants {
            let json = serde_json::to_string(&k).expect("serialize");
            let parsed: CredentialKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, k);
        }
    }

    #[test]
    fn newtypes_serialize_transparently() {
        // strong-typing skill: newtypes carry `#[serde(transparent)]` so they
        // serialize as bare strings, not as `{"0": "..."}`.
        let s = serde_json::to_string(&Scope::new("cone.send_message")).unwrap();
        assert_eq!(s, "\"cone.send_message\"");
        let h = serde_json::to_string(&HeaderName::try_new("authorization").unwrap()).unwrap();
        assert_eq!(h, "\"authorization\"");
    }

    #[test]
    fn nested_struct_with_credential_field_serializes_sentinel() {
        // Demonstrates the headline behavior: a domain struct containing a
        // `Credential<T>` field serializes that field as a sentinel ref,
        // even though the rest of the struct serializes normally.
        #[derive(Serialize)]
        struct LoginEvent {
            user_id: String,
            session: Credential<String>,
        }
        let minter = CredentialMinter::new_sealed(sample_issuer());
        let event = LoginEvent {
            user_id: "alice".to_string(),
            session: minter.mint("jwt-bytes".to_string(), sample_metadata()),
        };
        let json = serde_json::to_value(&event).expect("serialize");
        let session_field = json.get("session").expect("session field");
        let sentinel = session_field
            .get("$credential")
            .and_then(|v| v.as_str())
            .expect("sentinel string");
        assert_eq!(sentinel, event.session.id().as_str());
        // The user_id is normal.
        assert_eq!(json.get("user_id").and_then(|v| v.as_str()), Some("alice"));
        // The inner JWT bytes do not appear.
        let s = serde_json::to_string(&event).unwrap();
        assert!(!s.contains("jwt-bytes"), "inner JWT must not appear: {s}");
    }

    #[test]
    fn nested_struct_with_credential_emits_sidecar_under_guard() {
        // Mirrors the previous test but with the dispatch guard active —
        // the sidecar captures the inner value while the outer JSON still
        // contains only the sentinel.
        #[derive(Serialize)]
        struct LoginEvent {
            user_id: String,
            session: Credential<String>,
        }
        let minter = CredentialMinter::new_sealed(sample_issuer());
        let event = LoginEvent {
            user_id: "bob".to_string(),
            session: minter.mint("oauth-access".to_string(), sample_metadata()),
        };
        let (json, captured) =
            with_dispatch_capture(|| serde_json::to_value(&event).expect("serialize"));
        // Outer JSON: still sentinel.
        assert!(json.get("session").unwrap().get("$credential").is_some());
        // Sidecar: captured the value.
        let id = event.session.id();
        let entry = captured.get(id).expect("captured");
        assert_eq!(
            entry.value,
            serde_json::Value::String("oauth-access".into())
        );
    }

    #[test]
    fn multiple_credentials_get_distinct_ids() {
        // OAuth-style multi-credential return: each Credential<T> in the
        // event gets its own id and own sidecar entry under the guard.
        #[derive(Serialize)]
        struct TokenSet {
            access: Credential<String>,
            refresh: Credential<String>,
        }
        let minter = CredentialMinter::new_sealed(sample_issuer());
        let mut m_refresh = sample_metadata();
        m_refresh.kind = CredentialKind::OauthRefresh;
        let event = TokenSet {
            access: minter.mint("access-tok".to_string(), sample_metadata()),
            refresh: minter.mint("refresh-tok".to_string(), m_refresh),
        };
        assert_ne!(event.access.id(), event.refresh.id());
        let (_json, captured) =
            with_dispatch_capture(|| serde_json::to_value(&event).expect("serialize"));
        assert_eq!(captured.len(), 2);
        assert!(captured.contains_key(event.access.id()));
        assert!(captured.contains_key(event.refresh.id()));
    }
}
