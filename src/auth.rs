//! AuthContext and SessionValidator — relocated from plexus-core.
//!
//! Per AUTHZ-CORE-CRATE-1, the public type surface (fields, methods,
//! constructors) is preserved verbatim from plexus-core's previous home at
//! `plexus_core::plexus::auth`. The migration is mechanical; behavior is
//! unchanged. plexus-core re-exports these from here with a `#[deprecated]`
//! pointer at the new path so existing callers compile during the
//! deprecation window.
//!
//! Future work tightens the seal on `AuthContext::new` and the field
//! visibility (per AUTHZ-0 §"Crate-level isolation amplifies the seal").
//! That tightening is intentionally NOT in this ticket because it would
//! break ~30 direct construction sites across plexus-trak, plexus-transport
//! tests, and others — a workspace-wide blast radius outside this ticket's
//! scope. See `plans/AUTHZ/AUTHZ-CORE-CRATE-1-RUN-NOTES.md`.

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The metadata key under which a verified
/// [`Principal`](crate::identity::Principal) is stamped.
///
/// See [`AuthContext::principal`] for why the principal lives in `metadata`
/// rather than in a field of its own.
pub const PRINCIPAL_CLAIM: &str = "principal";

/// Per-connection authentication context, populated during WS upgrade.
///
/// This context is extracted from HTTP cookies (or other auth mechanisms) during
/// the WebSocket handshake and attached to the connection. Every RPC call on that
/// connection has access to this context.
///
/// # Multi-tenancy with Keycloak
///
/// When using Keycloak for multi-tenancy, the `AuthContext` typically contains:
/// - `user_id`: Keycloak user ID (sub claim from JWT)
/// - `session_id`: Keycloak session ID
/// - `roles`: User roles within the tenant/realm
/// - `metadata`: Additional JWT claims (realm, tenant ID, custom attributes)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuthContext {
    /// User identifier (e.g., Keycloak sub claim, user UUID)
    pub user_id: String,

    /// Session identifier (e.g., Keycloak session ID)
    pub session_id: String,

    /// User roles (e.g., ["user", "admin"], Keycloak realm roles)
    pub roles: Vec<String>,

    /// Additional metadata (e.g., JWT claims, tenant/realm info, custom attributes)
    /// For Keycloak multi-tenancy, this typically includes:
    /// - `realm`: Keycloak realm name
    /// - `tenant_id`: Organization/tenant identifier
    /// - Any custom claims from the JWT token
    pub metadata: Value,
}

impl AuthContext {
    /// Create a new AuthContext.
    ///
    /// # Note
    ///
    /// This constructor is `pub` to preserve the existing public API across
    /// the workspace. AUTHZ-0's structural-defense vision calls for this
    /// constructor to be `pub(crate)`; tightening that seal lands in a
    /// follow-up ticket because of the workspace-wide blast radius. See
    /// `plans/AUTHZ/AUTHZ-CORE-CRATE-1-RUN-NOTES.md`.
    pub fn new(user_id: String, session_id: String, roles: Vec<String>, metadata: Value) -> Self {
        Self {
            user_id,
            session_id,
            roles,
            metadata,
        }
    }

    /// Create an anonymous/unauthenticated context.
    ///
    /// This can be used as a fallback when methods accept `Option<&AuthContext>`
    /// and no authentication was provided.
    pub fn anonymous() -> Self {
        Self {
            user_id: "anonymous".to_string(),
            session_id: String::new(),
            roles: vec![],
            metadata: Value::Null,
        }
    }

    /// Create a context for a verified [`Principal`](crate::identity::Principal).
    ///
    /// The namespaced constructor: `user_id` is derived from the principal
    /// rather than supplied, so the two cannot be set to different things.
    /// Prefer building this through
    /// [`Authenticated::into_auth_context`](crate::identity::Authenticated::into_auth_context),
    /// which additionally requires a proof that authentication happened.
    pub fn for_principal(
        principal: &crate::identity::Principal,
        session_id: impl Into<String>,
        roles: Vec<String>,
        metadata: Value,
    ) -> Self {
        let mut map = match metadata {
            Value::Object(m) => m,
            Value::Null => serde_json::Map::new(),
            other => {
                let mut m = serde_json::Map::new();
                m.insert("claims".to_string(), other);
                m
            }
        };
        map.insert(
            PRINCIPAL_CLAIM.to_string(),
            Value::String(principal.to_string()),
        );
        Self {
            user_id: principal.as_legacy_user_id(),
            session_id: session_id.into(),
            roles,
            metadata: Value::Object(map),
        }
    }

    /// The caller's namespaced [`Principal`](crate::identity::Principal).
    ///
    /// # Why this is a method and not a field
    ///
    /// PLX-82 requires this to be **additive**, and `AuthContext` has all-`pub`
    /// fields that at least six sites across plexus-core, plexus-transport,
    /// and plexus-macros construct with an exhaustive struct literal —
    /// including `plexus_core::plexus::test_validator`, which is library code,
    /// not a test. Adding a sixth field would fail to compile every one of
    /// them, in crates this build is not permitted to modify. It would also
    /// change the `Deserialize` and `JsonSchema` shape of a type that crosses
    /// the wire.
    ///
    /// Deriving the principal instead costs nothing and buys something the
    /// field could not: **`principal` and `user_id` cannot disagree, because
    /// there is nowhere for them to disagree.** There is one storage location
    /// for an idp identity, and both accessors read it.
    ///
    /// # Resolution order
    ///
    /// 1. `metadata["principal"]`, if present and parseable — this is what
    ///    [`Authenticated::into_auth_context`] stamps, and it is the only
    ///    route by which a non-idp principal (a `nostr:` pubkey, an
    ///    `apikey:` id) can be carried.
    /// 2. Otherwise `idp:<user_id>`, when `user_id` is a canonical UUID —
    ///    the migration path for every context built before this build, and
    ///    for any [`SessionValidator`] not yet ported to an
    ///    [`Authenticator`](crate::identity::Authenticator).
    ///
    /// Returns `None` for anonymous contexts and for any `user_id` that is
    /// not a plexus-idp UUID. `None` means "no principal can be named here",
    /// never "authenticated as someone else".
    ///
    /// # This is a claim, not an authorization
    ///
    /// Same caveat as [`AuthContext::tenant_id`]: holding a `Principal` says
    /// who the context names, not what it may do. The proof that
    /// authentication occurred is
    /// [`Authenticated`](crate::identity::Authenticated), which only an
    /// `Authenticator` produces.
    ///
    /// [`Authenticated::into_auth_context`]: crate::identity::Authenticated::into_auth_context
    pub fn principal(&self) -> Option<crate::identity::Principal> {
        if let Some(raw) = self.get_metadata_string(PRINCIPAL_CLAIM) {
            if let Ok(p) = raw.parse::<crate::identity::Principal>() {
                return Some(p);
            }
            // A present-but-unparseable stamp is a corrupt claim. Falling
            // through to the `user_id` derivation would answer a different
            // question than the one the stamp was trying to answer, so this
            // is a hard `None`.
            return None;
        }
        crate::identity::Principal::from_legacy_user_id(&self.user_id)
    }

    /// Check if this context represents an authenticated user.
    pub fn is_authenticated(&self) -> bool {
        self.user_id != "anonymous" && !self.session_id.is_empty()
    }

    /// Check if the user has a specific role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Get a metadata field as a string.
    pub fn get_metadata_string(&self, key: &str) -> Option<String> {
        self.metadata
            .get(key)
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// Get the tenant/realm from metadata (Keycloak multi-tenancy).
    ///
    /// Pre-UT-1 helper retained for compatibility. New code should prefer
    /// [`AuthContext::tenant_id`], which returns the typed
    /// [`TenantId`](crate::tenant::types::TenantId) and reads the
    /// `org_id` claim first (UT-S01 D3).
    pub fn tenant(&self) -> Option<String> {
        self.get_metadata_string("tenant_id")
            .or_else(|| self.get_metadata_string("realm"))
    }

    /// The caller's tenant identity as a typed
    /// [`TenantId`](crate::tenant::types::TenantId), if present.
    ///
    /// Reads `metadata["org_id"]` first (the tenancy claim pinned by
    /// UT-S01 D3 — Auth0 Organizations convention), falling back to the
    /// legacy `metadata["tenant_id"]` key for one deprecation window
    /// (validators write the value under both keys during that window).
    ///
    /// Returns `None` when neither key is present **or** when the value
    /// fails `TenantId` validation (empty / overlong / non-printable) —
    /// a malformed tenant claim must not flow into comparisons as if it
    /// named a real tenant.
    ///
    /// Note this is the *claim*, not authorization: tenancy enforcement
    /// routes through the sealed [`Tenant`](crate::Tenant) minted by a
    /// [`TenantResolver`](crate::TenantResolver), and the
    /// [`TenantGate`](crate::TenantGate) predicates compare against that.
    pub fn tenant_id(&self) -> Option<crate::tenant::types::TenantId> {
        self.get_metadata_string("org_id")
            .or_else(|| self.get_metadata_string("tenant_id"))
            .and_then(|s| crate::tenant::types::TenantId::try_new(s).ok())
    }

    /// Framework-only constructor: derive a callee `AuthContext` from a
    /// caller context and a [`ForwardDerivation`].
    ///
    /// This is the **only** path that mints a callee context from a
    /// caller's. It is `pub(crate)` to `plexus-auth-core` — no downstream
    /// crate can reach it. A [`ForwardPolicy`] impl returns a
    /// `ForwardDerivation` (parameters); the framework dispatch path
    /// (AUTHLANG-3 wires this into `plexus_core::route_to_child`) is the
    /// only caller of this constructor. Per AUTHZ-0 §"The sealed-type
    /// pattern": the policy proposes; the framework disposes.
    ///
    /// The `_immediate_caller_stamp` parameter is reserved for the
    /// principal-chain extension that AUTHLANG-3 lands (it will append the
    /// stamp to the callee's invocation chain when `AuthContext` grows the
    /// chain field — today's `AuthContext` does not carry one, so the
    /// parameter is bound for forward compatibility and accepted but
    /// otherwise ignored). Surfacing it now keeps the constructor's
    /// signature stable across the AUTHZ-0 sealed-context migration.
    ///
    /// # Derivation semantics
    ///
    /// Each flag on the derivation maps to a logical field group on the
    /// current `AuthContext`:
    ///
    /// - `keep_verified_user` — retains `user_id` and `session_id` (the
    ///   identity of the originator). When `false`, both are reset to
    ///   `AuthContext::anonymous`'s values (`"anonymous"` / empty).
    /// - `keep_roles` — retains the role vector. When `false`, the
    ///   callee's `roles` is empty.
    /// - `keep_capabilities` — reserved for the AUTHZ-DATA / AUTHZ-CRED
    ///   migration; today's `AuthContext` carries no capabilities field, so
    ///   this flag is a no-op. Surfacing it keeps the v1 policy shape
    ///   forward-compatible.
    /// - `keep_metadata` — retains the metadata bag. When `false`, the
    ///   callee's `metadata` is `Value::Null`.
    ///
    /// The constructor never grows the context: every field in the
    /// returned `AuthContext` is either copied from `caller_ctx` or reset
    /// to the corresponding empty value. There is no path through this
    /// function that adds an unrelated role or fabricates a user_id.
    ///
    /// [`ForwardDerivation`]: crate::forward::ForwardDerivation
    /// [`ForwardPolicy`]: crate::forward::ForwardPolicy
    ///
    pub(crate) fn derive_callee_context(
        caller_ctx: &AuthContext,
        derivation: &crate::forward::ForwardDerivation,
        _immediate_caller_stamp: &crate::principal::Principal,
    ) -> AuthContext {
        let (user_id, session_id) = if derivation.keep_verified_user {
            (caller_ctx.user_id.clone(), caller_ctx.session_id.clone())
        } else {
            ("anonymous".to_string(), String::new())
        };
        let roles = if derivation.keep_roles {
            caller_ctx.roles.clone()
        } else {
            Vec::new()
        };
        // `keep_capabilities` is a no-op today: the current AuthContext has no
        // capabilities field. The flag is preserved on `ForwardDerivation` for
        // forward compatibility with the AUTHZ-DATA / AUTHZ-CRED migration.
        let mut metadata = if derivation.keep_metadata {
            caller_ctx.metadata.clone()
        } else {
            Value::Null
        };
        // The principal stamp lives in `metadata` (see `AuthContext::principal`),
        // so dropping the verified user has to drop the stamp too. Without
        // this, `keep_verified_user: false` + `keep_metadata: true` would reset
        // `user_id` to "anonymous" while `principal()` kept answering with the
        // caller's identity — the derivation would leak exactly the thing it
        // was asked to strip.
        if !derivation.keep_verified_user {
            if let Value::Object(ref mut map) = metadata {
                map.remove(PRINCIPAL_CLAIM);
            }
        }
        AuthContext {
            user_id,
            session_id,
            roles,
            metadata,
        }
    }

    /// Scoped-callback API for deriving a callee context.
    ///
    /// The framework's dispatch path (plexus-core `route_to_child`) calls
    /// this with a `ForwardDerivation` and a caller-principal stamp; the
    /// closure receives the derived callee `AuthContext` by value and
    /// returns whatever the dispatch yields (typically a `Future`).
    /// Passing by value rather than reference is intentional: it allows
    /// the closure to move the callee into an async block so dispatch can
    /// await the child call while the callee lives inside the future's
    /// state machine.
    ///
    /// This is the public entry point for AUTHLANG-3. The underlying
    /// constructor [`derive_callee_context`] remains `pub(crate)` so the
    /// raw "mint a callee from a caller" symbol is not callable from
    /// outside `plexus-auth-core`. Anyone can still call `AuthContext::new`
    /// and craft their own context from scratch — what they cannot do is
    /// obtain one through the framework-blessed derivation path except
    /// inside this callback, where the lifetime is scoped to the dispatch
    /// invocation.
    ///
    /// Per AUTHZ-0 §"The sealed-type pattern": the policy proposes (via
    /// `ForwardDerivation`); the framework disposes (via this callback).
    pub fn with_callee_context<F, R>(
        &self,
        derivation: &crate::forward::ForwardDerivation,
        immediate_caller_stamp: &crate::principal::Principal,
        f: F,
    ) -> R
    where
        F: FnOnce(AuthContext) -> R,
    {
        f(Self::derive_callee_context(self, derivation, immediate_caller_stamp))
    }
}

/// Backends implement this trait to validate cookies/tokens during WS upgrade.
///
/// This trait is designed to be object-safe and work with async/await, allowing
/// backends to use any authentication mechanism:
/// - JWT validation (e.g., Keycloak tokens)
/// - Database session lookups
/// - Redis session stores
/// - OAuth token introspection
///
/// # Example: Keycloak JWT Validation
///
/// ```rust,ignore
/// use plexus_auth_core::{AuthContext, SessionValidator};
/// use async_trait::async_trait;
///
/// struct KeycloakValidator {
///     jwks_client: JwksClient,
///     realm: String,
/// }
///
/// #[async_trait]
/// impl SessionValidator for KeycloakValidator {
///     async fn validate(&self, cookie_value: &str) -> Option<AuthContext> {
///         // Parse JWT from cookie
///         let token = parse_jwt_from_cookie(cookie_value)?;
///
///         // Validate signature and claims
///         let claims = self.jwks_client.verify(&token).await.ok()?;
///
///         // Extract user info and tenant from JWT claims
///         Some(AuthContext::new(
///             claims.sub,
///             claims.sid.unwrap_or_default(),
///             claims.realm_access.roles,
///             serde_json::json!({
///                 "realm": self.realm,
///                 "tenant_id": claims.get("tenant_id"),
///                 "email": claims.email,
///             }),
///         ))
///     }
/// }
/// ```
#[async_trait]
pub trait SessionValidator: Send + Sync + 'static {
    /// Validate a cookie header value and return an AuthContext if valid.
    ///
    /// # Arguments
    ///
    /// * `cookie_value` - The raw Cookie header value (e.g., "session=abc123; path=/")
    ///
    /// # Returns
    ///
    /// - `Some(AuthContext)` if the cookie is valid and represents an authenticated session
    /// - `None` if the cookie is invalid, expired, or represents an anonymous session
    ///
    /// # Implementation Notes
    ///
    /// - This is called during the WebSocket handshake (HTTP upgrade)
    /// - Validation should be fast to avoid blocking the connection
    /// - For JWT: verify signature, check expiration, extract claims
    /// - For session-based auth: lookup session in DB/Redis
    /// - Return None for invalid/expired credentials (connection proceeds as anonymous)
    async fn validate(&self, cookie_value: &str) -> Option<AuthContext>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_context_creation() {
        let ctx = AuthContext::new(
            "user-123".to_string(),
            "sess-456".to_string(),
            vec!["admin".to_string()],
            serde_json::json!({"tenant_id": "acme"}),
        );

        assert_eq!(ctx.user_id, "user-123");
        assert_eq!(ctx.session_id, "sess-456");
        assert!(ctx.has_role("admin"));
        assert!(!ctx.has_role("user"));
        assert_eq!(ctx.tenant(), Some("acme".to_string()));
        assert!(ctx.is_authenticated());
    }

    #[test]
    fn test_auth_context_clone() {
        let ctx = AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec!["admin".to_string()],
            serde_json::json!({"org": "acme"}),
        );

        let cloned = ctx.clone();
        assert_eq!(ctx.user_id, cloned.user_id);
        assert_eq!(ctx.session_id, cloned.session_id);
        assert_eq!(ctx.roles, cloned.roles);
    }

    #[test]
    fn test_anonymous_context() {
        let ctx = AuthContext::anonymous();
        assert_eq!(ctx.user_id, "anonymous");
        assert!(!ctx.is_authenticated());
        assert!(ctx.roles.is_empty());
    }

    #[test]
    fn test_role_checking() {
        let ctx = AuthContext::new(
            "user-1".to_string(),
            "sess-1".to_string(),
            vec!["user".to_string(), "editor".to_string()],
            Value::Null,
        );

        assert!(ctx.has_role("user"));
        assert!(ctx.has_role("editor"));
        assert!(!ctx.has_role("admin"));
    }

    #[test]
    fn test_metadata_access() {
        let ctx = AuthContext::new(
            "user-1".to_string(),
            "sess-1".to_string(),
            vec![],
            serde_json::json!({
                "tenant_id": "org-123",
                "realm": "production",
                "email": "user@example.com"
            }),
        );

        assert_eq!(
            ctx.get_metadata_string("tenant_id"),
            Some("org-123".to_string())
        );
        assert_eq!(
            ctx.get_metadata_string("realm"),
            Some("production".to_string())
        );
        assert_eq!(
            ctx.get_metadata_string("email"),
            Some("user@example.com".to_string())
        );
        assert_eq!(ctx.get_metadata_string("nonexistent"), None);
    }


    #[test]
    fn derive_callee_context_identity_only_strips_roles_and_metadata() {
        use crate::forward::ForwardDerivation;
        use crate::principal::Principal;

        let caller = AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec!["admin".to_string(), "editor".to_string()],
            serde_json::json!({"tenant_id": "acme"}),
        );
        let stamp = Principal::anonymous_sealed();
        let callee = AuthContext::derive_callee_context(
            &caller,
            &ForwardDerivation::IDENTITY_ONLY,
            &stamp,
        );
        assert_eq!(callee.user_id, "alice");
        assert_eq!(callee.session_id, "sess-1");
        assert!(callee.roles.is_empty());
        assert_eq!(callee.metadata, Value::Null);
    }

    #[test]
    fn derive_callee_context_pass_through_retains_all_fields() {
        use crate::forward::ForwardDerivation;
        use crate::principal::Principal;

        let caller = AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec!["admin".to_string()],
            serde_json::json!({"tenant_id": "acme", "k": "v"}),
        );
        let stamp = Principal::anonymous_sealed();
        let callee = AuthContext::derive_callee_context(
            &caller,
            &ForwardDerivation::PASS_THROUGH,
            &stamp,
        );
        assert_eq!(callee.user_id, caller.user_id);
        assert_eq!(callee.session_id, caller.session_id);
        assert_eq!(callee.roles, caller.roles);
        assert_eq!(callee.metadata, caller.metadata);
    }

    #[test]
    fn derive_callee_context_anonymous_drops_everything() {
        use crate::forward::ForwardDerivation;
        use crate::principal::Principal;

        let caller = AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec!["admin".to_string()],
            serde_json::json!({"tenant_id": "acme"}),
        );
        let stamp = Principal::anonymous_sealed();
        let callee = AuthContext::derive_callee_context(
            &caller,
            &ForwardDerivation::ANONYMOUS,
            &stamp,
        );
        assert_eq!(callee.user_id, "anonymous");
        assert_eq!(callee.session_id, "");
        assert!(callee.roles.is_empty());
        assert_eq!(callee.metadata, Value::Null);
        assert!(!callee.is_authenticated());
    }

    #[test]
    fn with_callee_context_invokes_closure_with_derived_callee() {
        use crate::forward::ForwardDerivation;
        use crate::principal::Principal;

        let caller = AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec!["admin".to_string()],
            serde_json::json!({"tenant_id": "org-1"}),
        );
        let stamp = Principal::anonymous_sealed();

        let observed_user_id =
            caller.with_callee_context(&ForwardDerivation::IDENTITY_ONLY, &stamp, |callee| {
                assert!(callee.roles.is_empty());
                assert_eq!(callee.metadata, Value::Null);
                callee.user_id
            });

        assert_eq!(observed_user_id, "alice");
    }

    #[test]
    fn with_callee_context_returns_closure_value() {
        use crate::forward::ForwardDerivation;
        use crate::principal::Principal;

        let caller = AuthContext::anonymous();
        let stamp = Principal::anonymous_sealed();
        let answer =
            caller.with_callee_context(&ForwardDerivation::PASS_THROUGH, &stamp, |_| 42_u32);
        assert_eq!(answer, 42);
    }

    #[test]
    fn derive_callee_context_never_grows_context() {
        // Sanity: the constructor cannot fabricate fields that did not
        // exist on the caller. Starting from anonymous, even pass_through
        // produces anonymous — the derivation can keep what the caller
        // had, but never add what the caller lacked.
        use crate::forward::ForwardDerivation;
        use crate::principal::Principal;

        let caller = AuthContext::anonymous();
        let stamp = Principal::anonymous_sealed();
        let callee = AuthContext::derive_callee_context(
            &caller,
            &ForwardDerivation::PASS_THROUGH,
            &stamp,
        );
        assert_eq!(callee.user_id, "anonymous");
        assert!(callee.roles.is_empty());
        assert_eq!(callee.metadata, Value::Null);
        assert!(!callee.is_authenticated());
    }

    // PLX-82: the principal stamp lives in `metadata`, so a derivation that
    // drops the verified user must drop the stamp with it. Without the
    // removal in `derive_callee_context`, PASS_THROUGH-with-anonymous-identity
    // would reset `user_id` to "anonymous" while `principal()` kept answering
    // with the caller — leaking exactly what was asked to be stripped.
    #[test]
    fn dropping_the_verified_user_also_drops_the_principal_stamp() {
        use crate::forward::ForwardDerivation;
        use crate::identity::Principal as Subject;
        use crate::principal::Principal;

        let subject: Subject = "idp:6ba7b810-9dad-11d1-80b4-00c04fd430c8".parse().unwrap();
        let caller = AuthContext::for_principal(
            &subject,
            "sess-1",
            vec!["admin".to_string()],
            serde_json::json!({"org_id": "acme"}),
        );
        assert_eq!(caller.principal(), Some(subject.clone()));

        let stamp = Principal::anonymous_sealed();

        // Kept: identity survives, and both views agree.
        let kept =
            AuthContext::derive_callee_context(&caller, &ForwardDerivation::PASS_THROUGH, &stamp);
        assert_eq!(kept.principal(), Some(subject));
        assert_eq!(kept.user_id, "6ba7b810-9dad-11d1-80b4-00c04fd430c8");

        // Dropped: `user_id` is anonymized AND the stamp is gone.
        let dropped =
            AuthContext::derive_callee_context(&caller, &ForwardDerivation::ANONYMOUS, &stamp);
        assert_eq!(dropped.user_id, "anonymous");
        assert_eq!(dropped.principal(), None);

        // The dangerous combination specifically: metadata kept, identity not.
        let mixed = ForwardDerivation {
            keep_verified_user: false,
            keep_roles: false,
            keep_capabilities: false,
            keep_metadata: true,
        };
        let mixed = AuthContext::derive_callee_context(&caller, &mixed, &stamp);
        assert_eq!(mixed.user_id, "anonymous");
        assert_eq!(
            mixed.principal(),
            None,
            "keep_metadata must not smuggle the caller's principal through"
        );
        // Non-identity metadata is still retained.
        assert_eq!(mixed.get_metadata_string("org_id").as_deref(), Some("acme"));
    }

    #[test]
    fn for_principal_and_new_agree_on_an_idp_identity() {
        use crate::identity::Principal as Subject;

        let uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let subject: Subject = format!("idp:{uuid}").parse().unwrap();

        let stamped = AuthContext::for_principal(&subject, "s", vec![], Value::Null);
        let legacy = AuthContext::new(uuid.to_string(), "s".to_string(), vec![], Value::Null);

        assert_eq!(stamped.user_id, legacy.user_id);
        assert_eq!(stamped.principal(), legacy.principal());
    }

    #[test]
    fn tenant_id_prefers_org_id_claim() {
        // UT-1 / UT-S01 D3: `org_id` is the tenancy claim; `tenant_id` is
        // the one-release deprecation alias.
        let ctx = AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec![],
            serde_json::json!({"org_id": "org_acme", "tenant_id": "legacy"}),
        );
        assert_eq!(
            ctx.tenant_id().map(|t| t.as_str().to_string()),
            Some("org_acme".to_string())
        );
    }

    #[test]
    fn tenant_id_falls_back_to_legacy_tenant_id_claim() {
        let ctx = AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec![],
            serde_json::json!({"tenant_id": "acme"}),
        );
        assert_eq!(
            ctx.tenant_id().map(|t| t.as_str().to_string()),
            Some("acme".to_string())
        );
    }

    #[test]
    fn tenant_id_is_none_when_absent_or_malformed() {
        let absent = AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec![],
            serde_json::json!({"realm": "prod"}),
        );
        assert!(absent.tenant_id().is_none());

        // Malformed (control byte) must not surface as a usable TenantId.
        let malformed = AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec![],
            serde_json::json!({"org_id": "evil\u{0000}org"}),
        );
        assert!(malformed.tenant_id().is_none());
    }

    #[test]
    fn test_tenant_from_metadata() {
        // tenant_id takes precedence
        let ctx1 = AuthContext::new(
            "user-1".to_string(),
            "sess-1".to_string(),
            vec![],
            serde_json::json!({"tenant_id": "org-123", "realm": "prod"}),
        );
        assert_eq!(ctx1.tenant(), Some("org-123".to_string()));

        // Falls back to realm if no tenant_id
        let ctx2 = AuthContext::new(
            "user-1".to_string(),
            "sess-1".to_string(),
            vec![],
            serde_json::json!({"realm": "prod"}),
        );
        assert_eq!(ctx2.tenant(), Some("prod".to_string()));

        // None if neither present
        let ctx3 = AuthContext::new(
            "user-1".to_string(),
            "sess-1".to_string(),
            vec![],
            Value::Null,
        );
        assert_eq!(ctx3.tenant(), None);
    }
}
