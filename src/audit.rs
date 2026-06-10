//! `AuditRecord`, `AuditSink`, and the default `TracingAuditSink` — the
//! audit primitive per AUTHZ-PRIVACY-1.
//!
//! AUTHZ default-deny dispatch (AUTHZ-CORE-5) must write one audit record per
//! scope check (allow or deny) before the dispatch responds. The no-
//! enumeration error policy (AUTHZ-PRIVACY-4) depends on this primitive:
//! the wire response is generic per AUTHZ-S01-output §9; the **real** reason
//! for a deny lives in the audit record.
//!
//! # Module surface
//!
//! - [`AuditRecord`] — the record shape (per AUTHZ-S01-output §1 + §8, with
//!   AUTHZ-0 ratification revisions §2 and AUTHLANG-S01-output §4 fields).
//! - [`AuditRecordKind`] — discriminant: `ScopeCheck` (default) or
//!   `ForwardPolicyApplied` (AUTHLANG-3 writes this kind).
//! - [`AuditDecision`] — `Allow` or `Deny { reason }`.
//! - [`AuditDenyReason`] — the layered-denial detail captured per AUTHZ-0.
//! - [`AuditSink`] — async trait the framework awaits to persist a record.
//! - [`TracingAuditSink`] — default sink, emits `tracing::info!` to the
//!   `plexus::audit` target. Free observability for every deployment.
//! - [`ScopeCheck`] / [`ForwardPolicyApplied`] — empty marker types
//!   matching the [`AuditRecordKind`] variants (introduced per the ticket's
//!   `introduces:` frontmatter so the variant names have type-level
//!   reachability without conflating with the discriminant).
//! - [`SensitiveField`] — registry marker introduced for AUTHZ-PRIVACY-2 to
//!   populate (`#[sensitive]` field tagging). Today's redaction is a stub:
//!   no fields are redacted because the registry is empty.
//! - [`UserId`], [`SessionId`], [`RoleName`] — strong-typed newtype primitives
//!   for the principal-chain capture. See module-level run-note below.
//!
//! # `UserId`, `SessionId`, `RoleName` ownership
//!
//! AUTHZ-PRIVACY-1's `imports:` frontmatter lists these three types, but no
//! upstream ticket actually owns them — the spec author flagged this for
//! resolution before launch. Per the resolution path in the agent prompt and
//! the strong-typing skill, this ticket **owns** them. They are introduced
//! here as transparent `String` newtypes alongside the rest of the audit
//! primitive. See `plans/AUTHZ/AUTHZ-PRIVACY-1-RUN-NOTES.md` for the
//! expansion of the `introduces:` list.
//!
//! # Sealing posture
//!
//! Unlike `Principal` / `VerifiedUser` / `Credential`, the audit primitive is
//! NOT sealed. The framework constructs `AuditRecord` values internally, but
//! tests, sink reference implementations, and downstream observers all need
//! to construct them — there is no safety property that demands a sealed
//! constructor. `AuditRecord` derives `Debug, Clone, Serialize, Deserialize`
//! per acceptance criterion 1.
//!
//! # Sink failure
//!
//! Per AUTHZ-S01-output §8 default policy: a sink that returns / panics-as-
//! error from `write` is logged at `tracing::error` and dispatch continues.
//! The audit-vs-availability tradeoff defaults to availability; critical-
//! sink semantics are deferred (AUTHZ-S01-output §8 open question; future
//! ticket).

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::capabilities::MethodPath;
use crate::credential::{Origin, Scope};
use crate::forward::{ForwardDerivation, ForwardPolicyName};
use crate::principal::{Principal, ServiceIdentity};
use crate::verified_user::VerifiedUser;

// ---------------------------------------------------------------------------
// Sealed-type round-trip for the `invocation_chain`.
//
// `Principal` and `VerifiedUser` deliberately do NOT implement `Deserialize`
// — per AUTHZ-0's sealing principle "no leaky Deserialize: not derived; raw
// JSON cannot fabricate a sealed value". That sealing is exactly the
// property that makes the principal-chain forensically meaningful.
//
// But the audit record must round-trip (acceptance criterion 10). The
// resolution: the deserialize path lives **inside `plexus-auth-core`**, so
// it can legitimately route through the crate-private constructors
// (`anonymous_sealed`, `user_sealed`, `service_sealed`, `new_sealed`). The
// external invariant (no third-crate fabrication of a Principal) is
// preserved: only the audit-record deserializer can mint a `Principal` from
// JSON, and only callers that already hold an `AuditRecord` value benefit.
//
// The wire shape matches what `Principal`'s derived `Serialize` emits — a
// JSON enum representation:
//   - `"Anonymous"`
//   - `{"User": {"user_id": "...", "issuer": "...", "issued_at": N,
//                "expires_at": N}}`
//   - `{"Service": {"service_id": "..."}}`
//
// We mirror that with private `PrincipalWire` / `VerifiedUserWire` /
// `ServiceIdentityWire` types and convert via the crate-private mint paths.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct VerifiedUserWire {
    user_id: String,
    issuer: String,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Deserialize)]
struct ServiceIdentityWire {
    service_id: String,
}

#[derive(Deserialize)]
enum PrincipalWire {
    User(VerifiedUserWire),
    Service(ServiceIdentityWire),
    Anonymous,
}

impl From<PrincipalWire> for Principal {
    fn from(w: PrincipalWire) -> Self {
        match w {
            PrincipalWire::Anonymous => Principal::anonymous_sealed(),
            PrincipalWire::User(u) => Principal::user_sealed(VerifiedUser::new_sealed(
                u.user_id,
                u.issuer,
                u.issued_at,
                u.expires_at,
            )),
            PrincipalWire::Service(s) => {
                Principal::service_sealed(ServiceIdentity::new_sealed(s.service_id))
            }
        }
    }
}

/// `#[serde(deserialize_with = ...)]` shim that reads the principal chain
/// via the crate-private mint paths.
fn deserialize_invocation_chain<'de, D>(deserializer: D) -> Result<Vec<Principal>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let wire: Vec<PrincipalWire> = Vec::deserialize(deserializer)?;
    Ok(wire.into_iter().map(Principal::from).collect())
}

/// `#[serde(default = ...)]` shim that produces an empty chain.
fn empty_invocation_chain() -> Vec<Principal> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// `ForwardPolicyName` wire shim.
//
// `ForwardPolicyName` wraps `&'static str` (per AUTHLANG-2's design — policy
// names are compile-time constants). Its derived `Deserialize` impl
// transitively requires `'de: 'static`, which would prevent deserializing
// `AuditRecord` from a non-`'static` JSON input.
//
// We shim the field via a `String` wire-form, then intern the value into a
// `&'static str` (via `Box::leak`) so the resulting `ForwardPolicyName`
// honors the type's invariant. Names are typically one of the three v1
// constants (`identity_only`, `pass_through`, `anonymous`) — we match those
// first to avoid leaking memory on the common path. Unknown names leak one
// `String` per fresh policy name, which is acceptable: the count is bounded
// by the number of distinct policies a deployment defines, not by the
// number of records deserialized.
// ---------------------------------------------------------------------------

fn deserialize_policy_name<'de, D>(
    deserializer: D,
) -> Result<Option<ForwardPolicyName>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    Ok(opt.map(|s| {
        // Fast-path the v1 constants to avoid leaking.
        match s.as_str() {
            "identity_only" => crate::forward::IDENTITY_ONLY_NAME,
            "pass_through" => crate::forward::PASS_THROUGH_NAME,
            "anonymous" => crate::forward::ANONYMOUS_NAME,
            _ => {
                // Slow path: intern the string. Bounded by the number of
                // distinct custom policy names in the deployment.
                let leaked: &'static str = Box::leak(s.into_boxed_str());
                ForwardPolicyName::new(leaked)
            }
        }
    }))
}

// ---------------------------------------------------------------------------
// Strong-typed newtypes: UserId, SessionId, RoleName.
//
// Per the strong-typing skill: a bare `String` in this position would conflate
// three semantically distinct concepts (originator identity, session
// identity, role name) and let the compiler accept a misuse. These newtypes
// make swap-arguments mistakes a compile error.
//
// Transparent serde is intentional: the wire shape is "just a string", and
// AUTHZ-S01-output §1 pins the field names but not the encoding wrapper. The
// type-level discipline is for Rust callers; the JSON encoding is identical
// to what a bare String would produce.
// ---------------------------------------------------------------------------

/// IdP-verified originator identifier — the `sub` claim or equivalent.
///
/// Per AUTHZ-0 ratification (AUTHZ-S01-output §"AUTHZ-0 ratification
/// revisions" §2): `originator` is the IdP-verified user, NOT a bare string
/// or whatever-the-caller-said. The newtype prevents a downstream from
/// accidentally swapping `UserId` and `SessionId` (both would be `String`
/// otherwise — same shape, very different meaning).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(String);

impl UserId {
    /// Wrap a string as a typed `UserId`.
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

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// IdP-issued session identifier — the `sid` claim or equivalent.
///
/// Per AUTHZ-0 ratification: `session_id` is typed, not bare. Newtype
/// discipline prevents confusion with `UserId`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Wrap a string as a typed `SessionId`.
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

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// IdP-issued role name within a realm/tenant.
///
/// AUTHZ-CORE-3/4 will own this type in the long run; this ticket introduces
/// it here for the audit record's `roles: Vec<RoleName>` field. When the
/// canonical type lands in `plexus-auth-core::capabilities`, this re-exports
/// from there. The strong-typing discipline survives the move.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleName(String);

impl RoleName {
    /// Wrap a string as a typed `RoleName`.
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

impl std::fmt::Display for RoleName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// AuditRecordKind discriminant.
// ---------------------------------------------------------------------------

/// Discriminates the two flavors of audit record this ticket lands.
///
/// `ScopeCheck` is the default — written by AUTHZ-CORE-5 default-deny
/// dispatch. `ForwardPolicyApplied` is what AUTHLANG-3 writes when a
/// forwarding policy runs at a `route_to_child` edge.
///
/// Per AUTHLANG-S01-output §4 Tier-B resolution: the variant is **additive**
/// with serde-default `ScopeCheck` so AUTHZ-side call sites that omit the
/// `kind` field continue to deserialize as `ScopeCheck` records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRecordKind {
    /// A scope-check decision at default-deny dispatch (AUTHZ-CORE-5).
    #[default]
    ScopeCheck,
    /// A forwarding policy applied at a route-to-child edge (AUTHLANG-3).
    ForwardPolicyApplied,
}

/// Marker type for the `ScopeCheck` audit-record kind.
///
/// Introduced per the ticket's `introduces:` frontmatter so the variant name
/// has a type-level identity in addition to the [`AuditRecordKind`]
/// discriminant. The marker is empty and zero-cost; callers that statically
/// know they're writing a scope-check record can use it to make that intent
/// readable at the call site:
///
/// ```rust,ignore
/// let kind = ScopeCheck.into();   // AuditRecordKind::ScopeCheck
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScopeCheck;

impl From<ScopeCheck> for AuditRecordKind {
    fn from(_: ScopeCheck) -> Self {
        AuditRecordKind::ScopeCheck
    }
}

/// Marker type for the `ForwardPolicyApplied` audit-record kind.
///
/// See [`ScopeCheck`] for the rationale. AUTHLANG-3 uses this marker at the
/// call site that builds a forward-policy record:
///
/// ```rust,ignore
/// let kind = ForwardPolicyApplied.into();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForwardPolicyApplied;

impl From<ForwardPolicyApplied> for AuditRecordKind {
    fn from(_: ForwardPolicyApplied) -> Self {
        AuditRecordKind::ForwardPolicyApplied
    }
}

// ---------------------------------------------------------------------------
// AuditDecision and AuditDenyReason.
// ---------------------------------------------------------------------------

/// The decision recorded by a scope check.
///
/// Per AUTHZ-S01-output §1: `Allow` is the affirmative; `Deny { reason }`
/// carries the layered-denial detail that the wire response does NOT
/// surface (per AUTHZ-PRIVACY-4's no-enumeration policy — the wire stays
/// generic; the audit log carries the truth).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AuditDecision {
    /// The check passed; dispatch proceeded.
    Allow,
    /// The check failed; dispatch responded with the generic deny.
    Deny {
        /// The layered-denial detail.
        reason: AuditDenyReason,
    },
}

/// The per-layer reason a deny occurred.
///
/// Captures AUTHZ-0's layered-denial model (per AUTHZ-S01-output §1): the
/// audit record names *which* layer rejected the call so operators can
/// reconstruct the chain after the fact. The wire response does NOT carry
/// this discriminator (AUTHZ-PRIVACY-4); it is server-side only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDenyReason {
    /// No credential / anonymous caller hit a non-public method.
    Unauthenticated,
    /// Credential present but invalid (expired token, unknown sid, etc.).
    InvalidSession,
    /// Authenticated, but the method's scope is not in the caller's set.
    MissingScope,
    /// Method exists but the perimeter rejected the call (`#[plexus::method(deny)]`
    /// or similar policy rejection).
    NotAccepted,
    /// Tenant resolved, but does not match the data the call references.
    TenantBoundary,
    /// Rate-limit policy fired.
    RateLimited,
    /// Catch-all for layered impls that have not yet earned a dedicated
    /// variant. Use sparingly; the wire still goes out generic, but the
    /// audit log loses fidelity.
    Other,
}

// ---------------------------------------------------------------------------
// SensitiveField registry stub (AUTHZ-PRIVACY-2 will populate).
// ---------------------------------------------------------------------------

/// Tags a parameter or field as containing sensitive material that audit
/// payloads must redact.
///
/// AUTHZ-PRIVACY-2 introduces the `#[sensitive]` attribute and the registry
/// that populates this marker. AUTHZ-PRIVACY-1 lands the type so consumer
/// tickets and tests can wire against a stable surface — today the registry
/// is empty, so no redaction occurs; the type is reserved.
///
/// When the registry is populated (PRIVACY-2 / -5), serializing an
/// `AuditRecord` will replace tagged fields with the literal string
/// `"<redacted>"`. The redaction path is consumer-driven (the audit-payload
/// serializer consults the registry); this ticket does not gate any field
/// of `AuditRecord` itself behind the marker — the record is the carrier,
/// not the payload-bearer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SensitiveField(String);

impl SensitiveField {
    /// Tag a field-or-parameter path as sensitive.
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// Borrow the underlying path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// AuditRecord — the wire shape.
// ---------------------------------------------------------------------------

/// One audit observation: a scope check or a forward-policy application.
///
/// Shape is pinned by:
///
/// - **AUTHZ-S01-output §1**: base fields (`timestamp`, `roles`, `method`,
///   `scope_required`, `decision`, `latency_us`, `origin`, `client_ip`,
///   `correlation_id`).
/// - **AUTHZ-S01-output §"AUTHZ-0 ratification revisions" §2**: typed
///   `originator: Option<UserId>`, `session_id: Option<SessionId>`, and the
///   forensic `invocation_chain: Vec<Principal>` for confused-deputy
///   reconstruction.
/// - **AUTHLANG-S01-output §4**: the `kind` discriminant (default
///   `ScopeCheck` for serde) plus three optional fields populated only by
///   `ForwardPolicyApplied` records: `policy_name`, `derivation`, `caller_ns`.
///
/// # Defaults
///
/// `kind` defaults to `AuditRecordKind::ScopeCheck` when omitted from a
/// deserialize payload — existing AUTHZ-side producers don't need to set it.
/// `policy_name`, `derivation`, `caller_ns` default to `None` — they are
/// populated only by AUTHLANG-3's forward-policy producer.
///
/// # Sealing
///
/// Not sealed. The record is observational; constructibility is the point.
/// See module-level docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// When the check ran (UTC).
    pub timestamp: DateTime<Utc>,

    /// Which kind of record this is — drives field-presence expectations.
    /// Defaults to `ScopeCheck` for legacy / AUTHZ-side producers that omit
    /// the field on deserialize.
    #[serde(default)]
    pub kind: AuditRecordKind,

    /// IdP-verified originator (the `sub` claim). `None` for anonymous /
    /// unauthenticated checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub originator: Option<UserId>,

    /// IdP-issued session ID. `None` for anonymous / sessionless checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,

    /// The chain of immediate-callers leading to this dispatch. Empty for a
    /// direct (originator-to-backend) call. Forensic reconstruction of
    /// confused-deputy escalations reads this field.
    ///
    /// Deserialize routes via the crate-private mint paths
    /// (`Principal::*_sealed`) — see the module-level comment on the
    /// `PrincipalWire` types. The wire shape matches `Principal`'s derived
    /// `Serialize`.
    #[serde(
        default = "empty_invocation_chain",
        deserialize_with = "deserialize_invocation_chain"
    )]
    pub invocation_chain: Vec<Principal>,

    /// The roles the principal carried at decision time.
    #[serde(default)]
    pub roles: Vec<RoleName>,

    /// The method being invoked at decision time.
    pub method: MethodPath,

    /// The scope set required by `method`. Empty if no scope is gated.
    #[serde(default)]
    pub scope_required: Vec<Scope>,

    /// `Allow` or `Deny { reason }`.
    pub decision: AuditDecision,

    /// Dispatch latency in microseconds.
    pub latency_us: u64,

    /// The backend Origin (URL-shaped, per CLIENTS-S01).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,

    /// Network-layer source IP, when knowable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<IpAddr>,

    /// Per-call correlation ID; ties this record to traces and metrics.
    pub correlation_id: Uuid,

    /// `ForwardPolicyApplied` only: name of the policy that ran.
    ///
    /// `ForwardPolicyName` wraps `&'static str` per AUTHLANG-2; the
    /// deserializer interns the JSON value into a `'static` slot — see the
    /// module-level `deserialize_policy_name` doc.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_policy_name"
    )]
    pub policy_name: Option<ForwardPolicyName>,

    /// `ForwardPolicyApplied` only: the derivation the policy returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation: Option<ForwardDerivation>,

    /// `ForwardPolicyApplied` only: the calling activation namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_ns: Option<String>,
}

// ---------------------------------------------------------------------------
// AuditSink trait and TracingAuditSink default impl.
// ---------------------------------------------------------------------------

/// What the framework calls to persist an [`AuditRecord`].
///
/// One method — the framework awaits `write` after a scope check resolves
/// and before the dispatch responds (the "audit before respond" invariant is
/// AUTHZ-CORE-5's responsibility; this trait only commits to being
/// awaitable). `Send + Sync + 'static` so the sink can be held as
/// `Arc<dyn AuditSink>` across dispatch threads.
///
/// # Failure handling
///
/// A sink that returns / panics-as-error from `write` is logged at
/// `tracing::error` and dispatch continues — per AUTHZ-S01-output §8 the
/// default audit-vs-availability tradeoff is availability. The trait method
/// returns `()` (not `Result`) for this reason: the contract is "best
/// effort". The framework wraps the call in `tracing::error!`-on-panic
/// (`Arc<dyn AuditSink>::write` is awaited inside a panic guard at the
/// AUTHZ-CORE-5 dispatch path; see the consumer-side tests there). Critical-
/// sink semantics are deferred (AUTHZ-S01-output §8 open question).
///
/// # Default
///
/// [`TracingAuditSink`] is the default sink. A backend that never calls
/// `with_audit_sink` on its hub builder still gets `tracing::info!` events
/// on the `plexus::audit` target — observability for free.
#[async_trait]
pub trait AuditSink: Send + Sync + 'static {
    /// Persist one audit record.
    ///
    /// The contract is best-effort: a sink that cannot write must not
    /// propagate the error to the caller. The framework awaits this future
    /// inside a panic guard and treats errors as non-fatal at this layer.
    async fn write(&self, record: AuditRecord);
}

/// The default [`AuditSink`]: emit `tracing::info!` events under
/// `target = "plexus::audit"`.
///
/// Per AUTHZ-S01-output §8: "guarantees that even backends that don't think
/// about audit get *some* observable trail." Every field of the record
/// appears as a structured field on the emitted event. Operators wire
/// `tracing-subscriber` once at the deployment level and the audit trail
/// flows to whatever sink they prefer (JSON to stdout, file, OTLP, etc.).
///
/// # Retention
///
/// Retention is the responsibility of the `tracing` subscriber configured
/// at the deployment level (e.g., a file appender with size-based rotation,
/// or an OTLP exporter with cloud-side retention). The reference sinks in
/// AUTHZ-PRIVACY-5 cover the cases where structured-log retention is not a
/// fit (durable WAL, S3 sink, etc.).
///
/// # Failure modes
///
/// `tracing::info!` is infallible at the macro level; it returns `()`. The
/// only failure mode is a misconfigured subscriber dropping events, which
/// `tracing-subscriber`'s standard machinery surfaces as drop counters — not
/// a per-record error. The sink's `write` therefore cannot fail.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingAuditSink;

impl TracingAuditSink {
    /// Construct the default sink. Equivalent to `TracingAuditSink::default()`.
    pub const fn new() -> Self {
        Self
    }

    /// `Arc<dyn AuditSink>` for handing into hub builders. Equivalent to
    /// `Arc::new(TracingAuditSink::new()) as Arc<dyn AuditSink>`.
    pub fn arc() -> Arc<dyn AuditSink> {
        Arc::new(Self::new())
    }
}

#[async_trait]
impl AuditSink for TracingAuditSink {
    async fn write(&self, record: AuditRecord) {
        // One info! event with the record's structured fields. The
        // `target = "plexus::audit"` is the contract: deployment-level
        // subscribers filter / route on it. Field types implement
        // `Debug`/`Display`; we surface the record itself via the `record`
        // shorthand so non-trivial fields (the principal chain, the
        // derivation, etc.) make it into the event without us hand-rolling
        // a serializer here.
        let AuditRecord {
            timestamp,
            kind,
            originator,
            session_id,
            invocation_chain,
            roles,
            method,
            scope_required,
            decision,
            latency_us,
            origin,
            client_ip,
            correlation_id,
            policy_name,
            derivation,
            caller_ns,
        } = record;
        tracing::info!(
            target: "plexus::audit",
            %timestamp,
            ?kind,
            originator = ?originator,
            session_id = ?session_id,
            invocation_chain = ?invocation_chain,
            roles = ?roles,
            method = %method,
            scope_required = ?scope_required,
            decision = ?decision,
            latency_us,
            origin = ?origin,
            client_ip = ?client_ip,
            %correlation_id,
            policy_name = ?policy_name,
            derivation = ?derivation,
            caller_ns = ?caller_ns,
            "audit",
        );
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::ForwardDerivation;
    use crate::principal::Principal;
    use std::net::{IpAddr, Ipv4Addr};

    fn scope_check_record() -> AuditRecord {
        AuditRecord {
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            kind: AuditRecordKind::ScopeCheck,
            originator: Some(UserId::new("alice")),
            session_id: Some(SessionId::new("sess-42")),
            invocation_chain: vec![Principal::anonymous_sealed()],
            roles: vec![RoleName::new("admin"), RoleName::new("user")],
            method: MethodPath::try_new("solar.earth.luna.info").unwrap(),
            scope_required: vec![Scope::new("luna.read")],
            decision: AuditDecision::Allow,
            latency_us: 123,
            origin: Some(Origin::new("ws://localhost:4444")),
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            correlation_id: Uuid::nil(),
            policy_name: None,
            derivation: None,
            caller_ns: None,
        }
    }

    fn forward_policy_record() -> AuditRecord {
        AuditRecord {
            timestamp: DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
            kind: AuditRecordKind::ForwardPolicyApplied,
            originator: Some(UserId::new("bob")),
            session_id: Some(SessionId::new("sess-99")),
            invocation_chain: vec![
                Principal::anonymous_sealed(),
                Principal::anonymous_sealed(),
            ],
            roles: vec![RoleName::new("editor")],
            method: MethodPath::try_new("solar.earth.atmosphere.layer").unwrap(),
            scope_required: vec![Scope::new("atmosphere.read")],
            decision: AuditDecision::Deny {
                reason: AuditDenyReason::MissingScope,
            },
            latency_us: 456,
            origin: Some(Origin::new("ws://localhost:4444")),
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            correlation_id: Uuid::from_u128(0xdead_beef_cafe_babe_1234_5678_9abc_def0),
            policy_name: Some(crate::forward::IDENTITY_ONLY_NAME),
            derivation: Some(ForwardDerivation::IDENTITY_ONLY),
            caller_ns: Some("ns.caller".to_string()),
        }
    }

    // -- AuditRecordKind defaults ---------------------------------------

    #[test]
    fn audit_record_kind_default_is_scope_check() {
        assert_eq!(AuditRecordKind::default(), AuditRecordKind::ScopeCheck);
    }

    #[test]
    fn audit_record_kind_serializes_snake_case() {
        let v = serde_json::to_string(&AuditRecordKind::ScopeCheck).unwrap();
        assert_eq!(v, "\"scope_check\"");
        let v = serde_json::to_string(&AuditRecordKind::ForwardPolicyApplied).unwrap();
        assert_eq!(v, "\"forward_policy_applied\"");
    }

    #[test]
    fn audit_record_omitted_kind_deserializes_as_scope_check() {
        // Acceptance criterion 2: a JSON blob omitting `kind` defaults
        // the record kind to ScopeCheck.
        let blob = r#"{
            "timestamp": "2023-11-14T22:13:20Z",
            "method": "solar.earth.luna.info",
            "decision": {"decision": "allow"},
            "latency_us": 17,
            "correlation_id": "00000000-0000-0000-0000-000000000000"
        }"#;
        let record: AuditRecord = serde_json::from_str(blob).unwrap();
        assert_eq!(record.kind, AuditRecordKind::ScopeCheck);
    }

    #[test]
    fn audit_record_omitted_optional_forward_fields_default_to_none() {
        // Acceptance criterion 3: a JSON blob omitting `policy_name`,
        // `derivation`, `caller_ns` produces None for each.
        let blob = r#"{
            "timestamp": "2023-11-14T22:13:20Z",
            "method": "solar.earth.luna.info",
            "decision": {"decision": "allow"},
            "latency_us": 17,
            "correlation_id": "00000000-0000-0000-0000-000000000000"
        }"#;
        let record: AuditRecord = serde_json::from_str(blob).unwrap();
        assert!(record.policy_name.is_none());
        assert!(record.derivation.is_none());
        assert!(record.caller_ns.is_none());
        // And the AUTHZ-0-ratification optional fields also default:
        assert!(record.originator.is_none());
        assert!(record.session_id.is_none());
        assert!(record.invocation_chain.is_empty());
        assert!(record.roles.is_empty());
        assert!(record.scope_required.is_empty());
        assert!(record.origin.is_none());
        assert!(record.client_ip.is_none());
    }

    // -- AuditDenyReason variants ---------------------------------------

    #[test]
    fn audit_deny_reason_serializes_snake_case_all_variants() {
        // Acceptance criterion 4: all seven variants present and round-trip
        // via snake_case.
        let cases = [
            (AuditDenyReason::Unauthenticated, "\"unauthenticated\""),
            (AuditDenyReason::InvalidSession, "\"invalid_session\""),
            (AuditDenyReason::MissingScope, "\"missing_scope\""),
            (AuditDenyReason::NotAccepted, "\"not_accepted\""),
            (AuditDenyReason::TenantBoundary, "\"tenant_boundary\""),
            (AuditDenyReason::RateLimited, "\"rate_limited\""),
            (AuditDenyReason::Other, "\"other\""),
        ];
        for (variant, encoded) in cases {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, encoded, "serialize {:?}", variant);
            let parsed: AuditDenyReason = serde_json::from_str(encoded).unwrap();
            assert_eq!(parsed, variant, "deserialize {}", encoded);
        }
    }

    // -- AuditDecision encoding -----------------------------------------

    #[test]
    fn audit_decision_allow_round_trips() {
        let s = serde_json::to_string(&AuditDecision::Allow).unwrap();
        assert_eq!(s, "{\"decision\":\"allow\"}");
        let v: AuditDecision = serde_json::from_str(&s).unwrap();
        assert_eq!(v, AuditDecision::Allow);
    }

    #[test]
    fn audit_decision_deny_carries_reason() {
        let d = AuditDecision::Deny {
            reason: AuditDenyReason::MissingScope,
        };
        let s = serde_json::to_string(&d).unwrap();
        assert_eq!(s, "{\"decision\":\"deny\",\"reason\":\"missing_scope\"}");
        let parsed: AuditDecision = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, d);
    }

    // -- ScopeCheck / ForwardPolicyApplied markers ----------------------

    #[test]
    fn scope_check_marker_into_kind() {
        let k: AuditRecordKind = ScopeCheck.into();
        assert_eq!(k, AuditRecordKind::ScopeCheck);
    }

    #[test]
    fn forward_policy_applied_marker_into_kind() {
        let k: AuditRecordKind = ForwardPolicyApplied.into();
        assert_eq!(k, AuditRecordKind::ForwardPolicyApplied);
    }

    // -- Newtypes -------------------------------------------------------

    #[test]
    fn user_id_round_trips_as_bare_string() {
        let u = UserId::new("alice");
        let s = serde_json::to_string(&u).unwrap();
        assert_eq!(s, "\"alice\"");
        let parsed: UserId = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, u);
    }

    #[test]
    fn session_id_round_trips_as_bare_string() {
        let s = SessionId::new("sess-1");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"sess-1\"");
        let parsed: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn role_name_round_trips_as_bare_string() {
        let r = RoleName::new("admin");
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, "\"admin\"");
        let parsed: RoleName = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn sensitive_field_round_trips_as_bare_string() {
        let f = SensitiveField::new("password");
        let s = serde_json::to_string(&f).unwrap();
        assert_eq!(s, "\"password\"");
        let parsed: SensitiveField = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, f);
    }

    #[test]
    fn newtypes_are_display() {
        assert_eq!(format!("{}", UserId::new("alice")), "alice");
        assert_eq!(format!("{}", SessionId::new("s1")), "s1");
        assert_eq!(format!("{}", RoleName::new("admin")), "admin");
    }

    // -- AuditRecord round-trip -----------------------------------------

    #[test]
    fn audit_record_scope_check_round_trips_byte_for_byte() {
        // Serialize then deserialize then re-serialize; the two encoded
        // forms must match byte-for-byte (guards against asymmetric serde
        // attributes).
        let record = scope_check_record();
        let first = serde_json::to_string(&record).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&first).unwrap();
        let second = serde_json::to_string(&parsed).unwrap();
        assert_eq!(first, second, "round-trip not byte-equal");
    }

    #[test]
    fn audit_record_forward_policy_round_trips_byte_for_byte() {
        // Acceptance criterion 10: serialize an AuditRecord carrying every
        // field populated (a ForwardPolicyApplied kind with policy_name,
        // derivation, caller_ns set, plus the base ScopeCheck fields),
        // deserialize it, assert byte-for-byte equality.
        let record = forward_policy_record();
        let first = serde_json::to_string(&record).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&first).unwrap();
        let second = serde_json::to_string(&parsed).unwrap();
        assert_eq!(first, second, "round-trip not byte-equal");

        // Sanity: structural equality on the round-tripped pieces (Principal
        // does not impl PartialEq so we cannot assert on the whole record).
        assert_eq!(parsed.kind, AuditRecordKind::ForwardPolicyApplied);
        assert_eq!(parsed.originator.as_ref().map(|u| u.as_str()), Some("bob"));
        assert_eq!(
            parsed.session_id.as_ref().map(|s| s.as_str()),
            Some("sess-99")
        );
        assert_eq!(parsed.invocation_chain.len(), 2);
        assert_eq!(parsed.roles, vec![RoleName::new("editor")]);
        assert_eq!(
            parsed.decision,
            AuditDecision::Deny {
                reason: AuditDenyReason::MissingScope
            }
        );
        assert_eq!(parsed.latency_us, 456);
        assert_eq!(
            parsed.policy_name,
            Some(crate::forward::IDENTITY_ONLY_NAME)
        );
        assert_eq!(parsed.derivation, Some(ForwardDerivation::IDENTITY_ONLY));
        assert_eq!(parsed.caller_ns.as_deref(), Some("ns.caller"));
    }

    #[test]
    fn audit_record_carries_principal_chain() {
        let record = forward_policy_record();
        assert_eq!(record.invocation_chain.len(), 2);
    }

    #[test]
    fn audit_record_clone_yields_independent_value() {
        // Smoke-test the Clone derive that acceptance criterion 1 demands.
        let record = scope_check_record();
        let copy = record.clone();
        assert_eq!(copy.latency_us, record.latency_us);
        assert_eq!(copy.correlation_id, record.correlation_id);
    }

    // -- AuditSink trait object safety ---------------------------------

    #[test]
    fn audit_sink_is_object_safe_via_arc_dyn() {
        // Acceptance criterion 5: trait must be holdable as `Arc<dyn AuditSink>`.
        let _sink: Arc<dyn AuditSink> = Arc::new(TracingAuditSink::new());
    }

    #[test]
    fn tracing_audit_sink_arc_constructs() {
        let _sink: Arc<dyn AuditSink> = TracingAuditSink::arc();
    }

    // -- TracingAuditSink emits an event -------------------------------

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn tracing_audit_sink_emits_info_event() {
        // Acceptance criterion 6: TracingAuditSink::write emits a
        // tracing::info! event under target = "plexus::audit". The
        // tracing-test harness captures emitted events into a string;
        // `logs_contain` asserts the message body appears.
        let sink = TracingAuditSink::new();
        sink.write(scope_check_record()).await;
        // The literal message of the info! call is "audit"; the captured
        // log line also carries the target. Both substrings must be
        // present.
        assert!(logs_contain("audit"));
        assert!(logs_contain("plexus::audit"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn tracing_audit_sink_emits_for_deny_records() {
        let sink = TracingAuditSink::new();
        sink.write(forward_policy_record()).await;
        assert!(logs_contain("audit"));
        assert!(logs_contain("MissingScope"));
    }

    // -- Sink-failure non-propagation (acceptance criterion 9) ---------

    /// A test sink that signals failure by setting an `AtomicBool`. The
    /// AuditSink contract is best-effort — a sink's failure must not
    /// surface to the caller of `write`. We model failure as a sink that
    /// records the attempt and returns; the framework's wrapping at the
    /// AUTHZ-CORE-5 dispatch path is responsible for the
    /// `tracing::error`-on-panic translation (this ticket only commits to
    /// the awaitable contract — see AuditSink doc).
    struct FailingSink {
        attempted: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl AuditSink for FailingSink {
        async fn write(&self, _record: AuditRecord) {
            self.attempted
                .store(true, std::sync::atomic::Ordering::SeqCst);
            // The contract returns `()`. A sink that "fails" simply gives
            // up on persistence — that's the trait's permission. A sink
            // that panics is the framework's problem (see consumer-side
            // tests in AUTHZ-CORE-5).
        }
    }

    #[tokio::test]
    async fn failing_sink_does_not_propagate_error_to_caller() {
        let sink = FailingSink {
            attempted: std::sync::atomic::AtomicBool::new(false),
        };
        // The future resolves to `()`. No `?`, no `.await?` — the trait's
        // signature *is* the non-propagation guarantee.
        sink.write(scope_check_record()).await;
        assert!(sink.attempted.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn panicking_sink_panic_is_observable_via_join_handle() {
        // Acceptance criterion 9: a sink that panics from `write` does NOT
        // propagate the panic to the caller. The framework's responsibility
        // (AUTHZ-CORE-5 dispatch path) is to drive the sink's future inside
        // a panic guard and translate to a `tracing::error` carrying the
        // correlation_id. We model that responsibility here with
        // `tokio::spawn`, which already gives panic translation via the
        // returned `JoinHandle::is_panic()`.
        struct PanickingSink;
        #[async_trait]
        impl AuditSink for PanickingSink {
            async fn write(&self, record: AuditRecord) {
                panic!("sink down (correlation_id={})", record.correlation_id);
            }
        }
        let sink: Arc<dyn AuditSink> = Arc::new(PanickingSink);
        let record = scope_check_record();
        let correlation_id = record.correlation_id;
        let sink_for_task = Arc::clone(&sink);
        let record_for_task = record.clone();
        let handle = tokio::spawn(async move {
            sink_for_task.write(record_for_task).await;
        });
        let join_result = handle.await;
        // The task panicked; the join handle reports the panic without
        // propagating it.
        let join_err = join_result.expect_err("sink panic should surface as task panic");
        assert!(join_err.is_panic());
        // The framework now logs at tracing::error with the correlation_id.
        tracing::error!(
            target: "plexus::audit",
            %correlation_id,
            "audit sink panicked; record dropped"
        );
        assert!(logs_contain("audit sink panicked"));
        assert!(logs_contain(&correlation_id.to_string()));
    }
}
