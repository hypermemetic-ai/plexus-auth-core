//! `TenantGate` — the generalized tenant-isolation predicate layer (UT-1).
//!
//! Extracted from plexus-trak's `src/tenant_gate.rs` per the UT-S01
//! decision ("TenantGate generalization: predicates/threat-model
//! generalize; only FacetStore coupling and `meta.extra["tenant"]`
//! placement are trak-specific — UT-1 extracts the gate pattern, not the
//! store coupling"). Any backend registers a gate per request and gets:
//!
//! - **reads scoped `not_found`** — a cross-tenant read denial is
//!   indistinguishable from "does not exist", so a foreign-tenant probe
//!   cannot use the gate as an existence oracle;
//! - **writes `forbidden`** — write denials on existing foreign resources
//!   use the honest signal (existence was already conceded by the create
//!   path);
//! - **anonymous writes `unauthenticated`** — every write requires a
//!   resolved tenant.
//!
//! # What generalized, what stayed behind
//!
//! The trak gate's *predicates* (`can_see` / `can_write`), its denial
//! taxonomy (`NotFound` / `Forbidden` / `Unauthenticated`), its
//! defense-in-depth `is_authenticated()` check, and its create-stamp /
//! update-preserve tenant-hop defenses are all backend-agnostic — they
//! live here now. What stayed in trak: the `FacetStore` plumbing (which
//! store call to make, how to walk subtrees/edges) and the storage
//! placement of the tenant tag (`meta.extra["tenant"]`). A backend
//! expresses the latter by implementing [`TenantTagged`] for its resource
//! type (or by calling the `Option<&TenantId>` predicate forms directly).
//!
//! # Threat model (inherited verbatim from the trak reference)
//!
//! The gate sits **after** session validation (the `AuthContext` is
//! trustworthy at this layer — forging it is outside the trust boundary)
//! and **before** the store. It defends:
//!
//! 1. **Cross-tenant reads** → [`GateDenial::NotFound`] (no existence
//!    oracle).
//! 2. **Cross-tenant writes** → [`GateDenial::Forbidden`].
//! 3. **Cross-tenant listing** → filter with [`TenantGate::can_see`] /
//!    [`TenantGate::visible`].
//! 4. **Tenant hopping via metadata** → on create, stamp the resource
//!    with [`TenantGate::stamp`] (the caller's *resolved* tenant — any
//!    forged value the caller supplied is overwritten); on update,
//!    preserve the existing resource's tag verbatim (backend-side data
//!    plumbing; see the adapter sketch below).
//! 5. **Anonymous writes** → [`GateDenial::Unauthenticated`].
//! 6. **Forged `AuthContext`** → [`TenantGate::from_auth`] rejects any
//!    context with `is_authenticated() == false` *before* consulting the
//!    resolver, even if it carries a tenancy claim (belt-and-suspenders
//!    on top of the resolver's own anonymity handling).
//!
//! # Sealing
//!
//! The gate's caller-tenant slot holds a sealed [`Tenant`], and the only
//! constructors are [`TenantGate::from_auth`] (which routes through a
//! [`TenantResolver`] — the sole mint path for `Tenant`) and
//! [`TenantGate::anonymous`]. There is no way to build a gate
//! pre-loaded with an attacker-chosen tenant: resolver implementations
//! outside this crate cannot mint a `Tenant` either (the
//! `mint_tenant_from_str` helper is crate-private).
//!
//! # Adapter shape: how trak swaps in (wave 3 — do NOT do this now)
//!
//! trak's `TenantGate` becomes a thin adapter over this type; behavior is
//! unchanged because the predicates are extracted verbatim:
//!
//! ```rust,ignore
//! // plexus-trak/src/tenant_gate.rs after the UT-1 cutover (wave 3).
//! use plexus_auth_core::{ClaimTenantResolver, GateDenial, TenantId, TenantTagged};
//!
//! /// trak's resources declare where their tenant tag lives.
//! impl TenantTagged for Facet {
//!     fn tenant_tag(&self) -> Option<TenantId> {
//!         self.meta
//!             .extra
//!             .get("tenant")
//!             .and_then(|v| v.as_str())
//!             .and_then(|s| TenantId::try_new(s).ok())
//!     }
//! }
//!
//! pub struct TenantGate {
//!     store: Arc<dyn FacetStore>,
//!     gate: plexus_auth_core::TenantGate, // the generalized predicates
//! }
//!
//! impl TenantGate {
//!     pub async fn from_auth(store: Arc<dyn FacetStore>, auth: Option<&AuthContext>) -> Self {
//!         let resolver = ClaimTenantResolver::new(); // org_id + tenant_id alias
//!         let gate = plexus_auth_core::TenantGate::from_auth(&resolver, auth).await;
//!         Self { store, gate }
//!     }
//!
//!     pub async fn get(&self, id: Uuid) -> Result<Facet, GateError> {
//!         let facet = match self.store.get_facet(id).await {
//!             Ok(f) => f,
//!             Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
//!             Err(e) => return Err(GateError::Store(e)),
//!         };
//!         self.gate.authorize_read_of(&facet)?; // GateDenial -> GateError via From
//!         Ok(facet)
//!     }
//!
//!     pub async fn create(&self, mut facet: Facet) -> Result<Facet, GateError> {
//!         // Caller's resolved tenant wins; forged meta values are discarded.
//!         let stamp = self.gate.stamp()?;
//!         facet.meta.extra.insert(
//!             "tenant".to_string(),
//!             serde_json::Value::String(stamp.as_str().to_string()),
//!         );
//!         self.store.create_facet(&facet).await?;
//!         Ok(facet)
//!     }
//!
//!     pub async fn list_children(&self, parent: Option<Uuid>) -> Result<Vec<Facet>, GateError> {
//!         let all = self.store.list_children(parent).await?;
//!         Ok(all.into_iter().filter(|f| self.gate.visible(f)).collect())
//!     }
//!     // update/delete: fetch existing, `self.gate.authorize_write_of(&existing)?`,
//!     // preserve the existing tenant tag verbatim (tenant-hop defense #4),
//!     // then write — exactly today's bodies with the predicate calls swapped.
//! }
//!
//! impl From<GateDenial> for GateError {
//!     fn from(d: GateDenial) -> Self {
//!         match d {
//!             GateDenial::NotFound => GateError::NotFound,
//!             GateDenial::Forbidden => GateError::Forbidden,
//!             GateDenial::Unauthenticated => GateError::Unauthenticated,
//!         }
//!     }
//! }
//! ```

use crate::auth::AuthContext;
use crate::tenant::resolver::TenantResolver;
use crate::tenant::types::{Tenant, TenantId};

/// Denial outcomes of the gate's authorization predicates.
///
/// The same underlying "you can't have this" signal is deliberately split
/// by *path*:
///
/// - read denials are [`NotFound`](Self::NotFound) — the caller must not
///   learn that a foreign-tenant resource exists;
/// - write denials on existing resources are
///   [`Forbidden`](Self::Forbidden) — existence was already conceded by
///   the create path, so the honest signal costs nothing;
/// - writes without a resolved tenant are
///   [`Unauthenticated`](Self::Unauthenticated).
///
/// Backends convert this into their own error enum (typically with a
/// `From` impl — see the adapter sketch in the module docs). The variants
/// intentionally carry no payload: there is nothing tenant-shaped that is
/// safe to leak to the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDenial {
    /// The resource does not exist OR the caller cannot see it —
    /// indistinguishable by design (existence-oracle defense).
    NotFound,
    /// The caller is authenticated but may not modify the target.
    Forbidden,
    /// The operation requires an authenticated caller with a resolved
    /// tenant.
    Unauthenticated,
}

impl std::fmt::Display for GateDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
            Self::Forbidden => f.write_str("forbidden"),
            Self::Unauthenticated => f.write_str("unauthenticated"),
        }
    }
}

impl std::error::Error for GateDenial {}

/// A resource that carries a tenant tag.
///
/// Backends implement this for their resource types so the gate's generic
/// conveniences ([`TenantGate::visible`], [`TenantGate::authorize_read_of`],
/// [`TenantGate::authorize_write_of`]) can read the tag without knowing
/// where the backend stores it (a column, a metadata bag, a key prefix…).
///
/// # Contract
///
/// - `None` means **public**: the resource belongs to no tenant and is
///   visible to everyone (including anonymous callers) and writable by
///   any *authenticated* tenant — the trak reference semantics.
/// - A stored tag that fails [`TenantId::try_new`] validation must NOT be
///   mapped to `None` (that would silently publish the resource).
///   Validation rules are broad (printable ASCII ≤ 256 bytes), so a
///   failing tag means corrupt data: prefer failing the request in the
///   backend layer before the gate is consulted.
pub trait TenantTagged {
    /// The tenant tag stored on this resource, or `None` if the resource
    /// is public (untenanted).
    fn tenant_tag(&self) -> Option<TenantId>;
}

/// The generalized tenant-isolation gate.
///
/// One gate is constructed per request via [`TenantGate::from_auth`] and
/// holds the caller's resolved [`Tenant`] (or `None` for anonymous /
/// unresolvable callers). All predicates compare that resolved tenant
/// against a resource's stored [`TenantId`] tag.
///
/// The visibility / write matrices (verbatim from the trak reference):
///
/// | caller     | resource tag | `can_see` | `can_write` |
/// |------------|--------------|-----------|-------------|
/// | anonymous  | public       | yes       | no          |
/// | anonymous  | tenant-owned | no        | no          |
/// | tenant `t` | public       | yes       | yes         |
/// | tenant `t` | tag == `t`   | yes       | yes         |
/// | tenant `t` | tag != `t`   | no        | no          |
pub struct TenantGate {
    /// The caller's resolved tenant. `None` ⇔ anonymous (or the resolver
    /// could not derive a tenant — treated identically, per the trak
    /// reference).
    tenant: Option<Tenant>,
}

impl TenantGate {
    /// Build a gate for the given caller context, resolving the tenant
    /// through the supplied [`TenantResolver`].
    ///
    /// Resolution flow (verbatim from the trak reference):
    ///
    /// 1. `auth == None` → anonymous gate.
    /// 2. `auth.is_authenticated() == false` → anonymous gate. This is
    ///    the defense-in-depth check: [`ClaimTenantResolver`] does not
    ///    itself check `is_authenticated()` when a claim is present, so a
    ///    hand-crafted `AuthContext` carrying a tenancy claim but no
    ///    valid session must be stopped here.
    /// 3. Otherwise the resolver runs; `Ok` → tenant gate, `Err` →
    ///    anonymous gate.
    ///
    /// Note the structural guarantee: the resolver is the *only* way a
    /// tenant enters the gate, and resolvers can only mint a [`Tenant`]
    /// through this crate's sealed paths.
    ///
    /// [`ClaimTenantResolver`]: crate::tenant::resolver::ClaimTenantResolver
    pub async fn from_auth(
        resolver: &dyn TenantResolver,
        auth: Option<&AuthContext>,
    ) -> Self {
        let tenant = match auth {
            None => None,
            Some(ctx) if !ctx.is_authenticated() => None,
            Some(ctx) => resolver.resolve(ctx).await.ok(),
        };
        Self { tenant }
    }

    /// Build an anonymous gate (no resolved tenant).
    ///
    /// Useful for code paths that must apply public-only visibility
    /// without an `AuthContext` in hand.
    pub fn anonymous() -> Self {
        Self { tenant: None }
    }

    /// The caller's resolved tenant, if any. `None` ⇔ anonymous.
    pub fn caller_tenant(&self) -> Option<&Tenant> {
        self.tenant.as_ref()
    }

    /// Is this gate anonymous (no resolved tenant)?
    pub fn is_anonymous(&self) -> bool {
        self.tenant.is_none()
    }

    // ─── Predicates (Option<&TenantId> forms) ────────────────────────────

    /// Visibility predicate: can the caller see a resource with this tag?
    ///
    /// See the matrix on the type-level docs.
    pub fn can_see(&self, resource_tag: Option<&TenantId>) -> bool {
        match (self.tenant.as_ref(), resource_tag) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some(_), None) => true,
            (Some(t), Some(tag)) => t == tag,
        }
    }

    /// Write predicate: can the caller mutate a resource with this tag?
    ///
    /// Writes always require a resolved tenant. A tenant can mutate
    /// public (untagged) resources and resources in its own tenant.
    pub fn can_write(&self, resource_tag: Option<&TenantId>) -> bool {
        match (self.tenant.as_ref(), resource_tag) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(t), Some(tag)) => t == tag,
        }
    }

    /// Authorize a read of a resource with this tag.
    ///
    /// Denials are [`GateDenial::NotFound`] — indistinguishable from a
    /// genuinely missing resource (existence-oracle defense). Backends
    /// should map their store's own not-found to the same error so the
    /// two paths collapse on the wire.
    pub fn authorize_read(&self, resource_tag: Option<&TenantId>) -> Result<(), GateDenial> {
        if self.can_see(resource_tag) {
            Ok(())
        } else {
            Err(GateDenial::NotFound)
        }
    }

    /// Authorize a write to an *existing* resource with this tag.
    ///
    /// - Anonymous callers → [`GateDenial::Unauthenticated`].
    /// - Foreign-tenant target → [`GateDenial::Forbidden`] (existence was
    ///   conceded by the create path; the honest signal is used).
    ///
    /// For not-yet-existing targets (create), use [`TenantGate::stamp`].
    pub fn authorize_write(&self, resource_tag: Option<&TenantId>) -> Result<(), GateDenial> {
        if self.tenant.is_none() {
            return Err(GateDenial::Unauthenticated);
        }
        if self.can_write(resource_tag) {
            Ok(())
        } else {
            Err(GateDenial::Forbidden)
        }
    }

    /// The tenant tag to stamp on a resource the caller is creating.
    ///
    /// Returns the caller's **resolved** tenant as a [`TenantId`] — the
    /// backend must overwrite any caller-supplied tag with this value
    /// (tenant-hop-via-create defense; see threat-model item 4).
    /// Anonymous callers cannot create: [`GateDenial::Unauthenticated`].
    pub fn stamp(&self) -> Result<TenantId, GateDenial> {
        self.tenant
            .as_ref()
            .map(TenantId::from)
            .ok_or(GateDenial::Unauthenticated)
    }

    // ─── Generic conveniences over TenantTagged ──────────────────────────

    /// [`can_see`](Self::can_see) over a [`TenantTagged`] resource —
    /// the filter predicate for list/search/traversal paths.
    pub fn visible<R: TenantTagged>(&self, resource: &R) -> bool {
        self.can_see(resource.tenant_tag().as_ref())
    }

    /// [`authorize_read`](Self::authorize_read) over a [`TenantTagged`]
    /// resource.
    pub fn authorize_read_of<R: TenantTagged>(&self, resource: &R) -> Result<(), GateDenial> {
        self.authorize_read(resource.tenant_tag().as_ref())
    }

    /// [`authorize_write`](Self::authorize_write) over a [`TenantTagged`]
    /// resource.
    pub fn authorize_write_of<R: TenantTagged>(&self, resource: &R) -> Result<(), GateDenial> {
        self.authorize_write(resource.tenant_tag().as_ref())
    }
}

impl std::fmt::Debug for TenantGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The tenant identifier is printable (Tenant: Display); there is
        // no inner store to elide — unlike Tenanted<S>, the gate holds
        // only the resolved tenant.
        f.debug_struct("TenantGate")
            .field(
                "tenant",
                &self.tenant.as_ref().map(Tenant::as_str).unwrap_or("<anonymous>"),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    //! Predicate-matrix tests mirroring the trak reference gate's
    //! in-module suite, plus the stamp / denial-mapping behaviors that
    //! are new public surface here. End-to-end adoption coverage (a
    //! non-trak backend using the gate) lives in
    //! `tests/tenant_gate_adoption.rs`.

    use super::*;
    use crate::tenant::resolver::ClaimTenantResolver;
    use serde_json::json;

    fn ctx_with_tenant(user: &str, tenant: &str) -> AuthContext {
        AuthContext::new(
            user.to_string(),
            "sess-1".to_string(),
            vec![],
            json!({"org_id": tenant}),
        )
    }

    fn tag(s: &str) -> TenantId {
        TenantId::try_new(s).unwrap()
    }

    async fn gate_for(auth: Option<&AuthContext>) -> TenantGate {
        TenantGate::from_auth(&ClaimTenantResolver::new(), auth).await
    }

    #[tokio::test]
    async fn anonymous_caller_sees_only_public_resources() {
        let gate = gate_for(None).await;
        assert!(gate.can_see(None));
        assert!(!gate.can_see(Some(&tag("acme"))));
    }

    #[tokio::test]
    async fn tenant_caller_sees_own_and_public() {
        let ctx = ctx_with_tenant("alice", "acme");
        let gate = gate_for(Some(&ctx)).await;
        assert!(gate.can_see(None));
        assert!(gate.can_see(Some(&tag("acme"))));
        assert!(!gate.can_see(Some(&tag("neon"))));
    }

    #[tokio::test]
    async fn anonymous_cannot_write_anything() {
        let gate = gate_for(None).await;
        assert!(!gate.can_write(None));
        assert!(!gate.can_write(Some(&tag("acme"))));
    }

    #[tokio::test]
    async fn tenant_writes_own_and_public_only() {
        let ctx = ctx_with_tenant("alice", "acme");
        let gate = gate_for(Some(&ctx)).await;
        assert!(gate.can_write(None));
        assert!(gate.can_write(Some(&tag("acme"))));
        assert!(!gate.can_write(Some(&tag("neon"))));
    }

    #[tokio::test]
    async fn read_denial_is_not_found() {
        // Existence-oracle defense: cross-tenant read == missing resource.
        let ctx = ctx_with_tenant("alice", "acme");
        let gate = gate_for(Some(&ctx)).await;
        assert_eq!(
            gate.authorize_read(Some(&tag("neon"))),
            Err(GateDenial::NotFound)
        );
        assert_eq!(gate.authorize_read(Some(&tag("acme"))), Ok(()));
        assert_eq!(gate.authorize_read(None), Ok(()));
    }

    #[tokio::test]
    async fn write_denials_split_unauthenticated_vs_forbidden() {
        let anon = gate_for(None).await;
        assert_eq!(
            anon.authorize_write(None),
            Err(GateDenial::Unauthenticated)
        );

        let ctx = ctx_with_tenant("alice", "acme");
        let gate = gate_for(Some(&ctx)).await;
        assert_eq!(
            gate.authorize_write(Some(&tag("neon"))),
            Err(GateDenial::Forbidden)
        );
        assert_eq!(gate.authorize_write(Some(&tag("acme"))), Ok(()));
        assert_eq!(gate.authorize_write(None), Ok(()));
    }

    #[tokio::test]
    async fn stamp_returns_resolved_tenant_for_create() {
        let ctx = ctx_with_tenant("alice", "acme");
        let gate = gate_for(Some(&ctx)).await;
        assert_eq!(gate.stamp().unwrap().as_str(), "acme");

        let anon = gate_for(None).await;
        assert_eq!(anon.stamp(), Err(GateDenial::Unauthenticated));
    }

    #[tokio::test]
    async fn forged_ctx_with_claim_but_no_session_is_rejected_by_gate() {
        // The layered defense inherited from the trak reference
        // (`forged_ctx_with_claim_but_no_session_is_rejected_by_gate`):
        // a hand-crafted AuthContext with a tenancy claim but an empty
        // session_id resolves to anonymous.
        let ctx = AuthContext::new(
            "alice".into(),
            String::new(), // empty session → !is_authenticated
            vec![],
            json!({"org_id": "acme"}),
        );
        let gate = gate_for(Some(&ctx)).await;
        assert!(gate.caller_tenant().is_none());
        assert!(gate.is_anonymous());
    }

    #[tokio::test]
    async fn unresolvable_caller_is_anonymous() {
        let ctx = AuthContext::new(
            "alice".into(),
            "sess-1".into(),
            vec![],
            json!({}), // no tenancy claim
        );
        // Disable the single-user fallback so resolution genuinely fails.
        let resolver = ClaimTenantResolver {
            claim_key: "org_id".into(),
            single_user_fallback: false,
        };
        let gate = TenantGate::from_auth(&resolver, Some(&ctx)).await;
        assert!(gate.is_anonymous());
    }

    #[tokio::test]
    async fn tenant_tagged_conveniences_mirror_predicates() {
        struct Note {
            tenant: Option<&'static str>,
        }
        impl TenantTagged for Note {
            fn tenant_tag(&self) -> Option<TenantId> {
                self.tenant.map(|t| TenantId::try_new(t).unwrap())
            }
        }

        let ctx = ctx_with_tenant("alice", "acme");
        let gate = gate_for(Some(&ctx)).await;

        let own = Note { tenant: Some("acme") };
        let foreign = Note { tenant: Some("neon") };
        let public = Note { tenant: None };

        assert!(gate.visible(&own));
        assert!(gate.visible(&public));
        assert!(!gate.visible(&foreign));

        assert_eq!(gate.authorize_read_of(&own), Ok(()));
        assert_eq!(gate.authorize_read_of(&foreign), Err(GateDenial::NotFound));
        assert_eq!(gate.authorize_write_of(&own), Ok(()));
        assert_eq!(
            gate.authorize_write_of(&foreign),
            Err(GateDenial::Forbidden)
        );
    }

    #[tokio::test]
    async fn debug_renders_tenant_or_anonymous() {
        let ctx = ctx_with_tenant("alice", "acme");
        let gate = gate_for(Some(&ctx)).await;
        assert!(format!("{gate:?}").contains("acme"));
        let anon = TenantGate::anonymous();
        assert!(format!("{anon:?}").contains("<anonymous>"));
    }

    #[test]
    fn gate_denial_display_matches_wire_vocabulary() {
        assert_eq!(format!("{}", GateDenial::NotFound), "not found");
        assert_eq!(format!("{}", GateDenial::Forbidden), "forbidden");
        assert_eq!(
            format!("{}", GateDenial::Unauthenticated),
            "unauthenticated"
        );
    }
}
