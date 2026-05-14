//! `Tenant` — sealed unit of data isolation.
//!
//! A `Tenant` value names an isolation unit (an organization, a workspace,
//! a user-as-their-own-tenant). Storage methods scope their queries by it.
//! Two `Tenant` values compare equal iff they refer to the same isolation
//! unit; equality is bytewise on the inner string.
//!
//! # Sealing
//!
//! `Tenant::try_new` is `pub(crate)`. Activation code in other crates
//! cannot call it. The only path to a `Tenant` value is through the
//! framework's `TenantResolver`, which derives one from a verified
//! `AuthContext`. Forging a tenant therefore requires forging the
//! `AuthContext`, which requires forging the IdP signature — outside the
//! trust boundary entirely.
//!
//! Per AUTHZ-0 §"The sealed-type pattern":
//!
//! - **No fabrication.** Constructor is crate-private.
//! - **No backdoor `From` / `Into`.** Orphan rules forbid foreign-trait
//!   impls for this foreign type from a third crate.
//! - **No accidental `Default`.** Not derived; a default tenant value
//!   would silently widen the isolation boundary.
//! - **No leaky `Deserialize`.** `Deserialize` IS derived (transparently
//!   over the inner string) so that `Tenant` round-trips through serde
//!   inside framework-owned structures (audit records, dispatch
//!   extensions). External RPC-parameter deserialization is gated by the
//!   macro layer (AUTHZ-DATA-2-MACRO): `&Tenant` is recognized as an
//!   extension-only parameter type and cannot be extracted from wire
//!   payloads. The `Deserialize` derive is therefore not a fabrication
//!   surface in practice.
//! - **No mutation.** Inner field is private; no setters.

use serde::{Deserialize, Serialize};

/// A sealed unit of data isolation.
///
/// `Tenant` wraps a validated string. The constructor is `pub(crate)`:
/// activation code in consuming crates receives `&Tenant` borrows from the
/// framework's dispatch extensions but cannot construct a `Tenant` itself.
///
/// # Carrier choice
///
/// `String` (not `Uuid`): real deployments emit tenant identifiers in
/// heterogeneous shapes (Keycloak UUIDs, Auth0 `auth0|<sub>` strings,
/// Google numeric IDs, enterprise SSO DN-style identifiers). A validated
/// `String` accepts all of these without an information-losing transform.
/// Backends that want stronger typing wrap `Tenant` in a per-backend
/// newtype.
///
/// # Validation rules
///
/// `Tenant::try_new` (crate-private) rejects:
///
/// - the empty string,
/// - inputs longer than 256 bytes,
/// - inputs containing any byte below `0x20` (control characters,
///   including NUL) or equal to `0x7f` (DEL).
///
/// These rules keep tenant identifiers safe to use as filename components,
/// SQL bind values, and audit log fields without further escaping.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tenant(String);

impl Tenant {
    /// Mint a `Tenant`. Crate-private — only `plexus-auth-core` (the
    /// framework's tenant-resolution path) calls this. Activation crates
    /// cannot reach it.
    ///
    /// Validation: non-empty, length ≤ 256 bytes, every byte in
    /// `0x20..=0x7e` (ASCII printable, excluding DEL).
    pub(crate) fn try_new(s: impl Into<String>) -> Result<Self, TenantError> {
        let s = s.into();
        if s.is_empty() || s.len() > 256 {
            return Err(TenantError::InvalidShape);
        }
        if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(TenantError::InvalidShape);
        }
        Ok(Self(s))
    }

    /// Borrow the inner identifier as `&str`.
    ///
    /// Use this for SQL binds, hash-map keys, audit log fields, and any
    /// other place that needs the underlying identifier shape. The
    /// returned `&str` shares the `Tenant`'s lifetime; it is not a fresh
    /// allocation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Tenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Layer-4 (data-isolation) failure modes.
///
/// The framework distinguishes these variants for audit purposes; the
/// dispatch layer converts all of them to a generic wire-side
/// `AuthzError::Forbidden { reason: TenantBoundary }` so no information is
/// leaked to the caller about which path failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantError {
    /// The candidate string failed `Tenant::try_new`'s validation rules.
    ///
    /// This variant is internal — it surfaces only inside resolver
    /// implementations that attempt to mint a `Tenant` from a malformed
    /// claim value. It never propagates to the wire.
    InvalidShape,

    /// The resolver ran but could not derive a tenant from the verified
    /// `AuthContext` (anonymous caller, claim missing, lookup empty).
    ///
    /// Converted by the dispatch layer to
    /// `AuthzError::Forbidden { reason: TenantBoundary }`; the original
    /// variant is captured in the `AuditRecord` for operator
    /// investigation, never in the wire response.
    UnresolvedFromAuthContext,

    /// A backend-supplied `TenantResolver` impl returned an error
    /// condition (e.g., a database lookup failed, an upstream service
    /// timed out). The carried message is for audit only.
    BackendResolverFailed(String),
}

impl std::fmt::Display for TenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidShape => f.write_str(
                "tenant identifier failed validation (empty, too long, or non-printable bytes)",
            ),
            Self::UnresolvedFromAuthContext => {
                f.write_str("could not derive a tenant from the verified AuthContext")
            }
            Self::BackendResolverFailed(msg) => {
                write!(f, "backend tenant resolver failed: {msg}")
            }
        }
    }
}

impl std::error::Error for TenantError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_new_accepts_typical_identifiers() {
        // Keycloak UUID shape.
        Tenant::try_new("a1b2c3d4-e5f6-4789-9abc-def012345678").unwrap();
        // Auth0 sub shape.
        Tenant::try_new("auth0|507f1f77bcf86cd799439011").unwrap();
        // Google numeric string.
        Tenant::try_new("110248495921238034044").unwrap();
        // Slug-style.
        Tenant::try_new("acme-corp").unwrap();
        // Single-user fallback uses a user id — short is fine.
        Tenant::try_new("alice").unwrap();
    }

    #[test]
    fn try_new_rejects_empty() {
        assert_eq!(Tenant::try_new(""), Err(TenantError::InvalidShape));
    }

    #[test]
    fn try_new_rejects_overlong() {
        let s = "a".repeat(257);
        assert_eq!(Tenant::try_new(s), Err(TenantError::InvalidShape));
    }

    #[test]
    fn try_new_accepts_max_length() {
        let s = "a".repeat(256);
        assert!(Tenant::try_new(s).is_ok());
    }

    #[test]
    fn try_new_rejects_control_bytes() {
        // NUL.
        assert_eq!(
            Tenant::try_new("alice\0bob"),
            Err(TenantError::InvalidShape)
        );
        // Newline.
        assert_eq!(Tenant::try_new("alice\n"), Err(TenantError::InvalidShape));
        // Tab.
        assert_eq!(Tenant::try_new("alice\t"), Err(TenantError::InvalidShape));
        // DEL (0x7f).
        assert_eq!(
            Tenant::try_new("alice\x7f"),
            Err(TenantError::InvalidShape)
        );
        // Below 0x20.
        assert_eq!(
            Tenant::try_new("alice\x1f"),
            Err(TenantError::InvalidShape)
        );
    }

    #[test]
    fn try_new_accepts_boundary_printable_bytes() {
        // 0x20 (space) and 0x7e (~) are the boundaries.
        Tenant::try_new(" ").unwrap();
        Tenant::try_new("~").unwrap();
        Tenant::try_new("tenant id with space").unwrap();
    }

    #[test]
    fn as_str_returns_inner_unchanged() {
        let t = Tenant::try_new("acme-corp").unwrap();
        assert_eq!(t.as_str(), "acme-corp");
    }

    #[test]
    fn display_renders_inner_unchanged() {
        let t = Tenant::try_new("acme-corp").unwrap();
        assert_eq!(format!("{t}"), "acme-corp");
    }

    #[test]
    fn equality_is_bytewise() {
        let a = Tenant::try_new("acme").unwrap();
        let b = Tenant::try_new("acme").unwrap();
        let c = Tenant::try_new("Acme").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn clone_preserves_value() {
        let a = Tenant::try_new("acme").unwrap();
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(a.as_str(), b.as_str());
    }

    #[test]
    fn serializes_transparently_as_bare_string() {
        let t = Tenant::try_new("alice").unwrap();
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s, r#""alice""#);
    }

    #[test]
    fn deserializes_transparently_from_bare_string() {
        let t: Tenant = serde_json::from_str(r#""alice""#).unwrap();
        assert_eq!(t.as_str(), "alice");
    }

    #[test]
    fn serde_round_trip_preserves_value() {
        let original = Tenant::try_new("auth0|507f1f77bcf86cd799439011").unwrap();
        let s = serde_json::to_string(&original).unwrap();
        let parsed: Tenant = serde_json::from_str(&s).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn hash_collisions_match_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Tenant::try_new("acme").unwrap());
        // Inserting an equal value is a no-op.
        assert!(!set.insert(Tenant::try_new("acme").unwrap()));
        assert!(set.insert(Tenant::try_new("Acme").unwrap()));
    }

    #[test]
    fn tenant_error_display_describes_each_variant() {
        assert!(format!("{}", TenantError::InvalidShape).contains("validation"));
        assert!(
            format!("{}", TenantError::UnresolvedFromAuthContext).contains("AuthContext")
        );
        assert!(format!(
            "{}",
            TenantError::BackendResolverFailed("db timeout".into())
        )
        .contains("db timeout"));
    }
}
