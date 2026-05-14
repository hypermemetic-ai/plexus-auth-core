//! Forwarding-policy primitives — `CallSite`, `ForwardDerivation`,
//! `ForwardPolicyName`, the `ForwardPolicy` trait, and the v1 named impls
//! (`IdentityOnly`, `PassThrough`, `Anonymous`).
//!
//! Per AUTHLANG-S01-output §1 (pinned design) and AUTHLANG-2.
//!
//! # Sealed-type invariant (load-bearing)
//!
//! A [`ForwardPolicy`] impl receives a sealed `&AuthContext` and a
//! `&CallSite` and returns a [`ForwardDerivation`] — **parameters** for
//! how to derive the callee's auth context, NOT a constructed
//! [`AuthContext`]. The framework consumes the derivation and mints the
//! next sealed context via [`crate::auth::AuthContext::derive_callee_context`],
//! which is `pub(crate)` to `plexus-auth-core`. Activations and other
//! downstream crates cannot reach that constructor.
//!
//! Per AUTHZ-0 §"The sealed-type pattern": the policy proposes; the
//! framework disposes. Policies can **shrink** a context (drop fields)
//! but never **grow** it (add or set fields). `ForwardDerivation`'s shape
//! enforces this structurally — every field is a "keep" flag; there is no
//! "add" or "set" knob.
//!
//! # Module surface
//!
//! - [`CallSite`] — one edge in the call graph at policy-run time.
//! - [`ForwardDerivation`] — a flag set returned by the policy.
//! - [`ForwardPolicyName`] — newtype identifying which policy ran (audit).
//! - [`ForwardPolicy`] trait — what custom impls implement.
//! - [`IdentityOnly`], [`PassThrough`], [`Anonymous`] — v1 built-ins.

use crate::auth::AuthContext;
use crate::method_path::MethodPath;
use crate::principal::Principal;
use serde::{Deserialize, Serialize};

/// Identifies a single edge in the call graph at the moment a policy runs.
///
/// Constructed by the framework at the dispatch point (`route_to_child` in
/// plexus-core, wired in by AUTHLANG-3) and passed to
/// [`ForwardPolicy::forward`]. Policies inspect it to make routing-aware
/// decisions (e.g., "PassThrough only when callee is in `audit.*`"); the
/// three built-in policies ignore it.
///
/// Per AUTHZ-0 vocabulary: `caller` and `callee`, NOT parent/child.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// The framework-stamped immediate-caller principal. Sealed value; the
    /// framework auto-stamps it at dispatch per AUTHZ-0 principle 6.
    pub caller: Principal,

    /// The fully qualified method path on the callee being invoked
    /// (e.g., `solar.earth.luna.info`).
    pub callee_method: MethodPath,
}

impl CallSite {
    /// Construct a `CallSite` from its sealed components.
    ///
    /// `CallSite` is a thin coupling of a sealed `Principal` with a
    /// validated `MethodPath`. It is not itself sealed beyond the seals on
    /// its fields: a downstream crate that already holds a `Principal` (it
    /// cannot — the constructors are `pub(crate)`) and a valid
    /// `MethodPath` could synthesize one. The construction path that
    /// matters in practice is the framework's `route_to_child` (AUTHLANG-3),
    /// which holds the only access to a freshly stamped `Principal`.
    pub fn new(caller: Principal, callee_method: MethodPath) -> Self {
        Self {
            caller,
            callee_method,
        }
    }
}

/// What a policy returns: a derivation request, NOT a constructed context.
///
/// The framework consumes this and mints the next sealed `AuthContext` for
/// the callee. The shape is **intentionally minimal** for v1 — four "keep"
/// flags, one per logical group of the caller's context. Future composable
/// primitives (AUTHLANG v2) will replace this with a richer combinator AST
/// without breaking the v1 trait signature.
///
/// # Derive-only invariant
///
/// Every field is a "keep" flag: forward this field from the caller to the
/// callee, or drop it. There is no "add this role" or "set this user_id"
/// knob. Policies cannot escalate authority across a boundary — the
/// most-permissive a callee context can be is exactly the caller's
/// context.
///
/// # Field-to-`AuthContext` mapping (today)
///
/// | Flag | Maps to fields on the current `AuthContext` |
/// |---|---|
/// | `keep_verified_user` | `user_id`, `session_id` (identity of the originator) |
/// | `keep_roles` | `roles` |
/// | `keep_capabilities` | (no field yet; reserved for AUTHZ-DATA / AUTHZ-CRED work) |
/// | `keep_metadata` | `metadata` |
///
/// `keep_capabilities` is intentionally surfaced now so the v1 shape is
/// forward-compatible: when the sealed-context migration adds a
/// capabilities field, no policy impl signature changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardDerivation {
    /// Forward the IdP-verified originator's identity (`user_id`, `session_id`).
    pub keep_verified_user: bool,
    /// Forward the caller's role set (`roles`).
    pub keep_roles: bool,
    /// Forward the caller's capability set. Reserved for the
    /// AUTHZ-DATA / AUTHZ-CRED migration; today this flag is a no-op on
    /// `AuthContext` because the field does not yet exist.
    pub keep_capabilities: bool,
    /// Forward the caller's opaque metadata bag (`metadata`).
    pub keep_metadata: bool,
}

impl ForwardDerivation {
    /// Identity-only: keep verified user; drop roles, capabilities, metadata.
    pub const IDENTITY_ONLY: Self = Self {
        keep_verified_user: true,
        keep_roles: false,
        keep_capabilities: false,
        keep_metadata: false,
    };

    /// Pass-through: keep every flag.
    pub const PASS_THROUGH: Self = Self {
        keep_verified_user: true,
        keep_roles: true,
        keep_capabilities: true,
        keep_metadata: true,
    };

    /// Anonymous: keep no flag.
    pub const ANONYMOUS: Self = Self {
        keep_verified_user: false,
        keep_roles: false,
        keep_capabilities: false,
        keep_metadata: false,
    };
}

/// Stable identifier for a forwarding policy, surfaced into audit records
/// and diagnostics.
///
/// `ForwardPolicyName` wraps a `&'static str` because the v1 named policies
/// are compile-time constants. Custom impls construct their names via
/// [`ForwardPolicyName::new`] (a `const fn`), so naming remains structural.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ForwardPolicyName(&'static str);

impl ForwardPolicyName {
    /// Construct a policy name from a `&'static str`. `const`-callable.
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// Borrow the underlying static string.
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for ForwardPolicyName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// The forwarding-policy trait.
///
/// v1 is intentionally minimal: one `name`, one infallible `forward`. A
/// custom impl receives the caller's sealed [`AuthContext`] and the
/// [`CallSite`] for the edge being dispatched, and returns a
/// [`ForwardDerivation`] describing which fields the framework should
/// retain when constructing the callee's context.
///
/// # Why infallible
///
/// The three built-in policies are pure tag manipulation. A fallible
/// variant would force every wire-in site to handle an error case that
/// none of the v1 built-ins can produce. Future fallible policies are a
/// sibling trait (`FallibleForwardPolicy`), added without breaking v1's
/// shape. See AUTHLANG-S01-output §1.
///
/// # Object safety
///
/// `Send + Sync + 'static` matches the existing `Arc<dyn ChildRouter>` and
/// `Arc<dyn AuditSink>` patterns in plexus-core, so wire-in code can hold
/// a `Arc<dyn ForwardPolicy>`.
pub trait ForwardPolicy: Send + Sync + 'static {
    /// Stable identifier for this policy. Used in audit records.
    fn name(&self) -> ForwardPolicyName;

    /// Derive forwarding parameters for the callee.
    ///
    /// Returns a `ForwardDerivation` — **parameters**, not a constructed
    /// context. The framework calls
    /// [`AuthContext::derive_callee_context`](crate::auth::AuthContext::derive_callee_context)
    /// with these parameters to mint the sealed callee context.
    fn forward(&self, caller_ctx: &AuthContext, site: &CallSite) -> ForwardDerivation;
}

// --- v1 named impls --------------------------------------------------------

/// The `identity_only` policy name (stable string surfaced in audit).
pub const IDENTITY_ONLY_NAME: ForwardPolicyName = ForwardPolicyName::new("identity_only");
/// The `pass_through` policy name (stable string surfaced in audit).
pub const PASS_THROUGH_NAME: ForwardPolicyName = ForwardPolicyName::new("pass_through");
/// The `anonymous` policy name (stable string surfaced in audit).
pub const ANONYMOUS_NAME: ForwardPolicyName = ForwardPolicyName::new("anonymous");

/// Identity-only: forwards the caller's IdP-verified user identity and
/// drops roles, capabilities, and metadata.
///
/// Recommended default. The callee learns *who* invoked it (so it can
/// re-evaluate authorization against its own scopes per AUTHZ-S01
/// default-deny) without inheriting the caller's *authority*. Fixes the
/// confused-deputy class for any callee that reads `raw_ctx`.
///
/// Mirror of: HTTP cookies + per-page server-side authorization.
#[derive(Debug, Clone, Copy)]
pub struct IdentityOnly;

impl ForwardPolicy for IdentityOnly {
    fn name(&self) -> ForwardPolicyName {
        IDENTITY_ONLY_NAME
    }
    fn forward(&self, _ctx: &AuthContext, _site: &CallSite) -> ForwardDerivation {
        ForwardDerivation::IDENTITY_ONLY
    }
}

/// Pass-through: forward every field of the caller's context.
///
/// Explicit opt-out for activations whose callees genuinely need the
/// caller's roles, capabilities, or metadata to make local decisions.
/// Activations declaring this policy should justify it in review — the
/// audit record will surface the choice on every dispatch.
#[derive(Debug, Clone, Copy)]
pub struct PassThrough;

impl ForwardPolicy for PassThrough {
    fn name(&self) -> ForwardPolicyName {
        PASS_THROUGH_NAME
    }
    fn forward(&self, _ctx: &AuthContext, _site: &CallSite) -> ForwardDerivation {
        ForwardDerivation::PASS_THROUGH
    }
}

/// Anonymous: drop the entire `AuthContext`.
///
/// Explicit lockdown. The callee sees no identity, no roles, no
/// capabilities. Use for activations that should NEVER inherit caller
/// context (e.g., a public-facing echo service whose responses must not
/// leak who invoked them).
#[derive(Debug, Clone, Copy)]
pub struct Anonymous;

impl ForwardPolicy for Anonymous {
    fn name(&self) -> ForwardPolicyName {
        ANONYMOUS_NAME
    }
    fn forward(&self, _ctx: &AuthContext, _site: &CallSite) -> ForwardDerivation {
        ForwardDerivation::ANONYMOUS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_callsite() -> CallSite {
        CallSite::new(
            Principal::anonymous_sealed(),
            MethodPath::try_new("solar.earth.luna.info").unwrap(),
        )
    }

    fn sample_ctx() -> AuthContext {
        AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec!["admin".to_string()],
            serde_json::json!({"tenant_id": "acme"}),
        )
    }

    #[test]
    fn identity_only_returns_identity_only_constant() {
        let policy = IdentityOnly;
        assert_eq!(policy.name(), IDENTITY_ONLY_NAME);
        assert_eq!(policy.name().as_str(), "identity_only");
        let d = policy.forward(&sample_ctx(), &sample_callsite());
        assert_eq!(d, ForwardDerivation::IDENTITY_ONLY);
        assert!(d.keep_verified_user);
        assert!(!d.keep_roles);
        assert!(!d.keep_capabilities);
        assert!(!d.keep_metadata);
    }

    #[test]
    fn pass_through_returns_pass_through_constant() {
        let policy = PassThrough;
        assert_eq!(policy.name(), PASS_THROUGH_NAME);
        assert_eq!(policy.name().as_str(), "pass_through");
        let d = policy.forward(&sample_ctx(), &sample_callsite());
        assert_eq!(d, ForwardDerivation::PASS_THROUGH);
        assert!(d.keep_verified_user);
        assert!(d.keep_roles);
        assert!(d.keep_capabilities);
        assert!(d.keep_metadata);
    }

    #[test]
    fn anonymous_returns_anonymous_constant() {
        let policy = Anonymous;
        assert_eq!(policy.name(), ANONYMOUS_NAME);
        assert_eq!(policy.name().as_str(), "anonymous");
        let d = policy.forward(&sample_ctx(), &sample_callsite());
        assert_eq!(d, ForwardDerivation::ANONYMOUS);
        assert!(!d.keep_verified_user);
        assert!(!d.keep_roles);
        assert!(!d.keep_capabilities);
        assert!(!d.keep_metadata);
    }

    #[test]
    fn three_constants_are_distinct() {
        // Sanity: the named constants are not accidentally equal.
        assert_ne!(ForwardDerivation::IDENTITY_ONLY, ForwardDerivation::PASS_THROUGH);
        assert_ne!(ForwardDerivation::IDENTITY_ONLY, ForwardDerivation::ANONYMOUS);
        assert_ne!(ForwardDerivation::PASS_THROUGH, ForwardDerivation::ANONYMOUS);
    }

    #[test]
    fn policy_holdable_as_trait_object() {
        // `Send + Sync + 'static` bound lets us store as `Arc<dyn ForwardPolicy>`,
        // which is how plexus-core's wire-in (AUTHLANG-3) will carry them.
        use std::sync::Arc;
        let policies: Vec<Arc<dyn ForwardPolicy>> = vec![
            Arc::new(IdentityOnly),
            Arc::new(PassThrough),
            Arc::new(Anonymous),
        ];
        let names: Vec<&'static str> = policies.iter().map(|p| p.name().as_str()).collect();
        assert_eq!(names, vec!["identity_only", "pass_through", "anonymous"]);
    }

    #[test]
    fn policy_name_display_uses_inner_string() {
        assert_eq!(format!("{}", IDENTITY_ONLY_NAME), "identity_only");
    }
}
