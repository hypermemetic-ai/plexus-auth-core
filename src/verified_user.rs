//! `VerifiedUser` — sealed proof that an IdP-signed token was verified.
//!
//! Possessing a `VerifiedUser` value is *proof* the framework verified an
//! IdP-signed token. The constructor is `pub(crate)` to plexus-auth-core,
//! so no other crate can fabricate one — the only path to producing a
//! `VerifiedUser` runs through the (forthcoming) verifier inside this crate.
//!
//! Per AUTHZ-0 §"The sealed-type pattern":
//!
//! - **No fabrication.** Constructor is crate-private.
//! - **No backdoor `From` / `Into`.** Orphan rules forbid foreign-trait
//!   impls for this foreign type from a third crate.
//! - **No accidental `Default`.** Not derived; a default would be
//!   anonymous-with-no-claims, easy to confuse with verified-anonymous.
//! - **No leaky `Deserialize`.** Not derived; raw JSON cannot fabricate a
//!   sealed value.
//! - **No mutation.** Fields are private; no setters.

use crate::tenant::types::TenantId;
use serde::Serialize;

/// Sealed proof that an IdP-signed token was verified.
///
/// Carries the verified claims that the framework extracted from the signed
/// token (`user_id`, `issuer`, `issued_at`, `expires_at`, and — per UT-1 —
/// the optional `tenant` sourced from the `org_id` claim). The presence of
/// a `VerifiedUser` value is itself the proof — there is no way to
/// construct one from outside `plexus-auth-core`.
///
/// # Sealing
///
/// The constructor is `pub(crate)`. Only the verifier inside this crate
/// (which validates the IdP signature) is able to mint a `VerifiedUser`.
/// `tests/compile_fail/seal_verified_user_construct.rs` asserts that no
/// external crate can construct one.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedUser {
    user_id: String,
    issuer: String,
    issued_at: i64,
    expires_at: i64,
    /// The verified tenant identity, sourced from the token's `org_id`
    /// claim (UT-S01 D3: `org_id` is the tenancy claim, Auth0
    /// Organizations convention). `None` ⇔ the token carried no `org_id`
    /// — a valid-but-tenantless user.
    tenant: Option<TenantId>,
}

impl VerifiedUser {
    /// Mint a new `VerifiedUser`.
    ///
    /// This is `pub(crate)` — only the verifier inside `plexus-auth-core`
    /// can call it. The OIDC validator (`crate::oidc`, UT-1 / UT-S01 D1)
    /// is the verifier this constructor was built to wait for: it mints a
    /// `VerifiedUser` only after RS256 signature + `iss`/`aud`/`exp`/`iat`
    /// validation succeeds. External crates that need a `VerifiedUser`
    /// route through that validator; they cannot construct one directly.
    pub(crate) fn new_sealed(
        user_id: String,
        issuer: String,
        issued_at: i64,
        expires_at: i64,
        tenant: Option<TenantId>,
    ) -> Self {
        Self {
            user_id,
            issuer,
            issued_at,
            expires_at,
            tenant,
        }
    }

    /// The verified user identifier (e.g., the `sub` claim of the JWT).
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// The token issuer (e.g., the `iss` claim).
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Token-issued-at unix timestamp.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Token expiry unix timestamp.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// The verified tenant identity (the token's `org_id` claim), if any.
    ///
    /// `None` means the token was valid but carried no `org_id` — a
    /// tenantless user (UT-S01 D3). Tenancy *authorization* still routes
    /// through the sealed [`Tenant`](crate::Tenant) via a
    /// [`TenantResolver`](crate::TenantResolver); this accessor exposes the
    /// verified claim itself.
    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_user_carries_claims() {
        // Crate-private constructor is reachable from inside the crate.
        let v = VerifiedUser::new_sealed(
            "alice".to_string(),
            "https://idp.example.com".to_string(),
            1_700_000_000,
            1_700_003_600,
            None,
        );
        assert_eq!(v.user_id(), "alice");
        assert_eq!(v.issuer(), "https://idp.example.com");
        assert_eq!(v.issued_at(), 1_700_000_000);
        assert_eq!(v.expires_at(), 1_700_003_600);
        assert!(v.tenant_id().is_none());
    }

    #[test]
    fn verified_user_carries_org_id_tenant() {
        // UT-1: a token whose `org_id` claim validated carries the typed
        // tenant identity on the sealed proof.
        let v = VerifiedUser::new_sealed(
            "alice".to_string(),
            "https://idp.example.com".to_string(),
            1_700_000_000,
            1_700_003_600,
            Some(TenantId::try_new("org_hypermemetic").unwrap()),
        );
        assert_eq!(
            v.tenant_id().map(TenantId::as_str),
            Some("org_hypermemetic")
        );
    }
}
