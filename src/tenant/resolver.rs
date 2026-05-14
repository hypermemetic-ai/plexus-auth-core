//! `TenantResolver` — derives a sealed `Tenant` from an `AuthContext`.
//!
//! The framework invokes a `TenantResolver` once per request, after
//! `SessionValidator::validate` produces the `AuthContext` and before
//! method-scope authorization runs. The resulting `Tenant` flows through
//! the dispatch as an extension; activation methods that declare a
//! `&Tenant` parameter extract it from there.
//!
//! Two reference implementations are provided:
//!
//! - [`ClaimTenantResolver`] — the 80% case: pull a configured claim out
//!   of `AuthContext.metadata` (default key: `"tenant_id"`). When the
//!   claim is absent and `single_user_fallback` is true, fall back to
//!   the verified user id (single-user-deployment safe default).
//!
//! - [`SingleTenantResolver`] — the explicit opt-out: always resolve to
//!   one fixed tenant value, regardless of the caller. Use this for
//!   single-user dev installs that want tenancy off; the opt-out is
//!   grep-able in the hub builder.
//!
//! See `plans/AUTHZ/AUTHZ-DATA-S01-output.md` §2 for the trait design.

use crate::auth::AuthContext;
use crate::tenant::types::{Tenant, TenantError};
use async_trait::async_trait;

/// Derives a sealed `Tenant` for an authenticated caller.
///
/// Backends register one resolver per hub via the hub builder
/// (`with_tenant_resolver`); the framework invokes it once per request
/// at dispatch entry, post-authentication and pre-method-scope-check.
///
/// # Failure handling
///
/// A `TenantError` result is converted by the dispatch layer to
/// `AuthzError::Forbidden { reason: TenantBoundary }`; the underlying
/// variant is captured in the `AuditRecord` (with
/// `AuditDenyReason::TenantBoundary`) for operator investigation. The
/// wire response is the generic forbidden error — no information is
/// leaked about whether the failure was a missing claim, a backend
/// lookup miss, or a malformed identifier.
///
/// # Bounds
///
/// The `Send + Sync + 'static` bounds are required by the framework's
/// dispatch invocation pattern; the resolver is shared as an
/// `Arc<dyn TenantResolver>` across all concurrent requests.
#[async_trait]
pub trait TenantResolver: Send + Sync + 'static {
    /// Derive the tenant for the verified caller.
    ///
    /// Implementations should:
    ///
    /// - Return `Ok(Tenant)` when the caller resolves cleanly.
    /// - Return `Err(TenantError::UnresolvedFromAuthContext)` when no
    ///   tenant can be derived (anonymous caller, missing claim, empty
    ///   lookup) — this is the typical denial path.
    /// - Return `Err(TenantError::BackendResolverFailed(...))` when an
    ///   internal lookup mechanism failed (database error, upstream
    ///   service timeout, etc.).
    ///
    /// The `Ok` value is constructed through this crate's framework-
    /// internal helpers (`mint_tenant_from_str`, crate-private), which
    /// validate and seal the value. Resolver implementations therefore
    /// cannot bypass the validation rules pinned on `Tenant`.
    async fn resolve(&self, auth: &AuthContext) -> Result<Tenant, TenantError>;
}

/// Framework-internal helper that mints a `Tenant` from a string.
///
/// This is the only path exposed to resolver implementations (which live
/// inside `plexus-auth-core`, so the `pub(crate)` constructor is
/// reachable). Future ticket AUTHZ-DATA-1-DISPATCH will expose this as
/// `pub(crate)` to plexus-core via a sealed mint trait; for now,
/// resolvers live in this crate alongside the type and use the
/// crate-private constructor directly.
///
/// Returns `TenantError::InvalidShape` if the candidate fails the
/// validation rules pinned on `Tenant`.
pub(crate) fn mint_tenant_from_str(s: impl Into<String>) -> Result<Tenant, TenantError> {
    Tenant::try_new(s)
}

/// Reference impl: derive the tenant from an `AuthContext` claim.
///
/// Reads a configured claim key from `AuthContext.metadata` (e.g.
/// `"tenant_id"`, `"realm"`, `"org_id"`). When `single_user_fallback`
/// is true and the claim is absent, falls back to the caller's
/// `user_id` so single-user deployments map each user 1:1 to their own
/// tenant by default.
///
/// # Why `single_user_fallback` defaults to `true`
///
/// AUTHZ-DATA-S01-output Q2 leans toward the dev-safe default: a
/// deployment without an explicit `tenant_id` claim should not silently
/// serve cross-user data. Falling back to the user id means a
/// misconfigured single-user install gets per-user isolation
/// automatically; deployments that want a hard "claim required" gate
/// flip the bool to `false`.
#[derive(Debug, Clone)]
pub struct ClaimTenantResolver {
    /// The metadata key to look up (e.g. `"tenant_id"`, `"realm"`,
    /// `"org_id"`).
    pub claim_key: String,
    /// When the claim is absent, fall back to the caller's `user_id` as
    /// the tenant value. The single-user-deployment safe default.
    pub single_user_fallback: bool,
}

impl ClaimTenantResolver {
    /// Construct with the default claim key `"tenant_id"` and
    /// `single_user_fallback = true`. Matches the existing
    /// `AuthContext::tenant()` helper's primary lookup key.
    pub fn new() -> Self {
        Self {
            claim_key: "tenant_id".into(),
            single_user_fallback: true,
        }
    }

    /// Construct with a custom claim key. `single_user_fallback`
    /// remains at the dev-safe `true` default; toggle the field
    /// directly if a strict "claim required" gate is needed.
    pub fn with_claim_key(claim_key: impl Into<String>) -> Self {
        Self {
            claim_key: claim_key.into(),
            single_user_fallback: true,
        }
    }
}

impl Default for ClaimTenantResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TenantResolver for ClaimTenantResolver {
    async fn resolve(&self, auth: &AuthContext) -> Result<Tenant, TenantError> {
        if let Some(claim) = auth.get_metadata_string(&self.claim_key) {
            return mint_tenant_from_str(claim);
        }
        if self.single_user_fallback && auth.is_authenticated() {
            return mint_tenant_from_str(auth.user_id.clone());
        }
        Err(TenantError::UnresolvedFromAuthContext)
    }
}

/// Reference impl: always resolve to one fixed tenant.
///
/// The explicit opt-out for single-user dev installs that want tenancy
/// off (or for deployments that want a deliberately single-tenant
/// posture). The opt-out is grep-able in the hub builder code: a
/// reviewer searching for `SingleTenantResolver` finds every deployment
/// that has consciously disabled multi-tenancy.
#[derive(Debug, Clone)]
pub struct SingleTenantResolver {
    fixed: Tenant,
}

impl SingleTenantResolver {
    /// Construct with the literal tenant value `"default"`.
    ///
    /// Panics only if `"default"` fails `Tenant::try_new` validation —
    /// which it cannot (non-empty, short, all printable ASCII). Encoded
    /// as `expect` so a future change to the validation rules surfaces
    /// the failure here rather than silently shipping a non-functional
    /// resolver.
    pub fn new() -> Self {
        Self {
            fixed: Tenant::try_new("default")
                .expect("the literal \"default\" satisfies Tenant::try_new validation"),
        }
    }

    /// Construct with a custom fixed tenant identifier.
    ///
    /// Returns an error if the candidate fails `Tenant::try_new`
    /// validation (empty, too long, non-printable bytes). The
    /// `pub(crate)` reach to the constructor is acceptable here
    /// because this builder is itself part of `plexus-auth-core`'s
    /// blessed API: a backend operator who calls `with_fixed("acme")`
    /// is explicitly opting in to a fixed tenant value at hub
    /// configuration time, exactly as AUTHZ-DATA-S01-output §2
    /// describes ("the opt-out is explicit and grep-able").
    pub fn with_fixed(value: impl Into<String>) -> Result<Self, TenantError> {
        Ok(Self {
            fixed: Tenant::try_new(value)?,
        })
    }
}

impl Default for SingleTenantResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TenantResolver for SingleTenantResolver {
    async fn resolve(&self, _auth: &AuthContext) -> Result<Tenant, TenantError> {
        Ok(self.fixed.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_with_metadata(user_id: &str, metadata: serde_json::Value) -> AuthContext {
        AuthContext::new(
            user_id.into(),
            "sess-1".into(),
            vec![],
            metadata,
        )
    }

    #[tokio::test]
    async fn claim_resolver_pulls_tenant_id_by_default() {
        let r = ClaimTenantResolver::new();
        let auth = ctx_with_metadata("alice", json!({"tenant_id": "acme-corp"}));
        let t = r.resolve(&auth).await.unwrap();
        assert_eq!(t.as_str(), "acme-corp");
    }

    #[tokio::test]
    async fn claim_resolver_honors_custom_claim_key() {
        let r = ClaimTenantResolver::with_claim_key("org_id");
        let auth = ctx_with_metadata("alice", json!({"org_id": "neon-9"}));
        let t = r.resolve(&auth).await.unwrap();
        assert_eq!(t.as_str(), "neon-9");
    }

    #[tokio::test]
    async fn claim_resolver_ignores_irrelevant_claims() {
        let r = ClaimTenantResolver {
            claim_key: "tenant_id".into(),
            single_user_fallback: false,
        };
        let auth = ctx_with_metadata("alice", json!({"realm": "prod"}));
        let err = r.resolve(&auth).await.unwrap_err();
        assert_eq!(err, TenantError::UnresolvedFromAuthContext);
    }

    #[tokio::test]
    async fn claim_resolver_falls_back_to_user_id_when_enabled() {
        let r = ClaimTenantResolver {
            claim_key: "tenant_id".into(),
            single_user_fallback: true,
        };
        let auth = ctx_with_metadata("alice-uuid", json!({}));
        let t = r.resolve(&auth).await.unwrap();
        assert_eq!(t.as_str(), "alice-uuid");
    }

    #[tokio::test]
    async fn claim_resolver_does_not_fall_back_when_disabled() {
        let r = ClaimTenantResolver {
            claim_key: "tenant_id".into(),
            single_user_fallback: false,
        };
        let auth = ctx_with_metadata("alice", json!({}));
        let err = r.resolve(&auth).await.unwrap_err();
        assert_eq!(err, TenantError::UnresolvedFromAuthContext);
    }

    #[tokio::test]
    async fn claim_resolver_rejects_anonymous_even_with_fallback() {
        let r = ClaimTenantResolver {
            claim_key: "tenant_id".into(),
            single_user_fallback: true,
        };
        let auth = AuthContext::anonymous();
        let err = r.resolve(&auth).await.unwrap_err();
        assert_eq!(err, TenantError::UnresolvedFromAuthContext);
    }

    #[tokio::test]
    async fn claim_resolver_surfaces_invalid_shape_when_claim_malformed() {
        let r = ClaimTenantResolver::new();
        // Claim contains a NUL — fails Tenant::try_new validation.
        let auth = ctx_with_metadata("alice", json!({"tenant_id": "evil\0tenant"}));
        let err = r.resolve(&auth).await.unwrap_err();
        assert_eq!(err, TenantError::InvalidShape);
    }

    #[tokio::test]
    async fn claim_resolver_prefers_claim_over_fallback() {
        let r = ClaimTenantResolver {
            claim_key: "tenant_id".into(),
            single_user_fallback: true,
        };
        let auth = ctx_with_metadata("alice", json!({"tenant_id": "acme-corp"}));
        let t = r.resolve(&auth).await.unwrap();
        // Claim wins over fallback to user_id.
        assert_eq!(t.as_str(), "acme-corp");
    }

    #[tokio::test]
    async fn single_tenant_resolver_returns_default() {
        let r = SingleTenantResolver::new();
        let auth = ctx_with_metadata("alice", json!({"tenant_id": "ignored"}));
        let t = r.resolve(&auth).await.unwrap();
        assert_eq!(t.as_str(), "default");
    }

    #[tokio::test]
    async fn single_tenant_resolver_ignores_metadata() {
        // The whole point: the AuthContext is irrelevant to the result.
        let r = SingleTenantResolver::new();
        let auth1 = ctx_with_metadata("alice", json!({"tenant_id": "acme"}));
        let auth2 = ctx_with_metadata("bob", json!({"tenant_id": "neon"}));
        let auth3 = AuthContext::anonymous();
        assert_eq!(r.resolve(&auth1).await.unwrap().as_str(), "default");
        assert_eq!(r.resolve(&auth2).await.unwrap().as_str(), "default");
        assert_eq!(r.resolve(&auth3).await.unwrap().as_str(), "default");
    }

    #[tokio::test]
    async fn single_tenant_resolver_with_custom_fixed_value() {
        let r = SingleTenantResolver::with_fixed("dev-tenant").unwrap();
        let auth = AuthContext::anonymous();
        let t = r.resolve(&auth).await.unwrap();
        assert_eq!(t.as_str(), "dev-tenant");
    }

    #[tokio::test]
    async fn single_tenant_resolver_rejects_invalid_fixed_value() {
        let err = SingleTenantResolver::with_fixed("").unwrap_err();
        assert_eq!(err, TenantError::InvalidShape);
        let err = SingleTenantResolver::with_fixed("evil\0").unwrap_err();
        assert_eq!(err, TenantError::InvalidShape);
    }

    #[tokio::test]
    async fn single_tenant_resolver_never_fails_after_construction() {
        // The trait method itself doesn't return an error path for this
        // impl; we exercise enough auth shapes to demonstrate that.
        let r = SingleTenantResolver::new();
        for auth in [
            AuthContext::anonymous(),
            ctx_with_metadata("alice", json!({})),
            ctx_with_metadata("bob", json!({"tenant_id": "weird"})),
        ] {
            assert!(r.resolve(&auth).await.is_ok());
        }
    }

    /// Sanity: the trait is object-safe (can be stored as
    /// `Arc<dyn TenantResolver>`). The hub builder relies on this.
    #[tokio::test]
    async fn resolver_is_object_safe() {
        use std::sync::Arc;
        let r: Arc<dyn TenantResolver> = Arc::new(SingleTenantResolver::new());
        let auth = AuthContext::anonymous();
        let t = r.resolve(&auth).await.unwrap();
        assert_eq!(t.as_str(), "default");
    }
}
