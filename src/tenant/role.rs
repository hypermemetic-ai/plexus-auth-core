//! [`TenantRole`] — what a principal is allowed to be inside a tenant.
//!
//! # Why this lives in plexus-auth-core and not in plexus-idp
//!
//! The membership *records* live in plexus-idp, because that is the crate
//! that owns the identity database. The role *vocabulary* cannot live
//! there. `plexus-core` and `plexus-substrate` depend on
//! `plexus-auth-core` and never on `plexus-idp` — that inversion is the
//! entire point of this crate — so a role type defined in the IdP would be
//! unnameable by the tenant mount gate (M4·C) and by every backend that
//! has to make a decision about what a member may do. Defining it twice is
//! the drift hazard PLX-87 collapsed for `Principal`; so it is defined
//! once, here, in the lowest crate that anyone needs to name it from.
//!
//! # Why an enumeration and not a string
//!
//! M4 exists because `org_id` was free text with nothing behind it. A
//! free-text `role` column is the same mistake one level down: every
//! authorization decision becomes a string comparison, and the storage
//! spelling, the check, and the caller's literal are three definitions
//! that drift apart. (Buzz's production `relay_members` — the reference
//! shape for the membership record itself — has exactly this problem: a
//! `TEXT` column with a `CHECK`, a Postgres `member_role` enum used by a
//! *different* table with a *different* value set, and Rust `String`
//! comparisons at every call site.) Here there is one enumeration, one
//! storage spelling, and one parse.
//!
//! # `TenantRole` is not [`Role`](crate::scope_registry::Role)
//!
//! This crate already has a type called `Role`, and they are genuinely
//! different concepts rather than a PLX-87 duplication:
//!
//! | | [`Role`](crate::scope_registry::Role) (R-0) | [`TenantRole`] (M4·B) |
//! |---|---|---|
//! | what it names | a deployment's authorization taxonomy | who administers a tenant |
//! | value set | **open** — any [`RoleName`](crate::scope_registry::RoleName) a backend registers | **closed** — exactly three |
//! | where it is defined | per-deployment, in a `ScopeRegistryBuilder` | here, in the type system |
//! | what it expands to | a set of [`Scope`](crate::scope_registry::Scope)s | nothing; it *is* the decision |
//! | where it is carried | the `roles` claim on a token | a membership row |
//!
//! A membership role is deliberately **not** stamped into the `roles`
//! claim. Those roles are the backend's scope taxonomy; conflating them
//! would let a tenant's `admin` silently mean whatever `admin` happens to
//! expand to in some unrelated backend's registry.
//!
//! # Failing closed
//!
//! [`TenantRole::parse`] returns an error for anything it does not
//! recognise. It never falls back to a default. A row carrying an
//! unrecognised role is a corrupted row, and the safe reading of a
//! corrupted role is not "member" — it is "this is unreadable, refuse".

use serde::{Deserialize, Serialize};

/// A role held by a principal *within one tenant*.
///
/// Roles are per-membership, not per-principal: the same principal may be
/// an `Owner` of one tenant and a `Member` of another. The ordering of the
/// variants is the privilege ordering, and [`Ord`] is derived so that
/// `Member < Admin < Owner` — used by [`TenantRole::outranks`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantRole {
    /// Belongs to the tenant. May act inside it; may not change who else
    /// belongs.
    Member,
    /// May invite new members and revoke members.
    Admin,
    /// May do everything an admin may, and additionally manage admins.
    /// Every tenant that has any members has at least one owner.
    Owner,
}

impl TenantRole {
    /// Every role, in ascending privilege order.
    ///
    /// Exhaustive by construction: adding a variant without adding it here
    /// is caught by `every_variant_is_listed_in_all` in this module's
    /// tests.
    pub const ALL: &'static [TenantRole] = &[Self::Member, Self::Admin, Self::Owner];

    /// The storage and wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    /// Parse the storage spelling.
    ///
    /// Unknown spellings are [`UnknownRole`], never a silently-accepted
    /// opaque string and never a default. This is the whole of the "roles
    /// are not free text" contract: there is no way to obtain a
    /// `TenantRole` from a string except by naming one that exists.
    pub fn parse(s: &str) -> Result<Self, UnknownRole> {
        match s {
            "member" => Ok(Self::Member),
            "admin" => Ok(Self::Admin),
            "owner" => Ok(Self::Owner),
            other => Err(UnknownRole(other.to_string())),
        }
    }

    /// Whether this role may issue invitations to its tenant.
    ///
    /// Owners and admins may; a plain member may not. This is the check
    /// that stops membership from being self-propagating.
    pub const fn can_invite(self) -> bool {
        matches!(self, Self::Admin | Self::Owner)
    }

    /// Whether this role may revoke another member's membership.
    pub const fn can_revoke(self) -> bool {
        matches!(self, Self::Admin | Self::Owner)
    }

    /// Whether `self` is strictly more privileged than `other`.
    ///
    /// An admin may act on members but not on other admins or on owners;
    /// an owner may act on anyone below them. Nobody outranks an owner, so
    /// an owner is never removable by another owner — deliberate: the last
    /// owner of a tenant must not be removable by an accident of ordering.
    pub fn outranks(self, other: Self) -> bool {
        self > other
    }
}

impl std::fmt::Display for TenantRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TenantRole {
    type Err = UnknownRole;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A role spelling that names no [`TenantRole`].
///
/// Carries the offending string for the audit log. It is deliberately its
/// own error type rather than a new
/// [`TenantError`](crate::tenant::TenantError) variant: `TenantError` is
/// not `#[non_exhaustive]`, so widening it would break every exhaustive
/// `match` downstream, and "that is not a role" is not a tenant-resolution
/// failure in any case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRole(pub String);

impl std::fmt::Display for UnknownRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown tenant role: `{}`", self.0)
    }
}

impl std::error::Error for UnknownRole {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_is_listed_in_all() {
        // Adding a variant without adding it to ALL breaks this.
        for role in TenantRole::ALL {
            // Exhaustive match: a new variant fails to compile here.
            match role {
                TenantRole::Member | TenantRole::Admin | TenantRole::Owner => {}
            }
        }
        assert_eq!(TenantRole::ALL.len(), 3);
    }

    #[test]
    fn storage_spelling_round_trips_for_every_role() {
        for &role in TenantRole::ALL {
            assert_eq!(TenantRole::parse(role.as_str()), Ok(role));
        }
    }

    #[test]
    fn unknown_spellings_are_rejected_not_defaulted() {
        // The `org_id` mistake, one level down: this must NOT become a
        // member, and it must NOT become an opaque accepted string.
        assert_eq!(
            TenantRole::parse("superuser"),
            Err(UnknownRole("superuser".into()))
        );
        assert_eq!(TenantRole::parse(""), Err(UnknownRole(String::new())));
        // Case is part of the spelling; there is exactly one rendering.
        assert_eq!(TenantRole::parse("Owner"), Err(UnknownRole("Owner".into())));
        assert_eq!(TenantRole::parse("OWNER"), Err(UnknownRole("OWNER".into())));
        // Whitespace is not trimmed — a padded value is a different value.
        assert_eq!(
            TenantRole::parse(" admin"),
            Err(UnknownRole(" admin".into()))
        );
    }

    #[test]
    fn from_str_agrees_with_parse() {
        assert_eq!("admin".parse::<TenantRole>(), Ok(TenantRole::Admin));
        assert!("nope".parse::<TenantRole>().is_err());
    }

    #[test]
    fn display_is_the_storage_spelling() {
        assert_eq!(format!("{}", TenantRole::Owner), "owner");
        assert_eq!(format!("{}", TenantRole::Admin), "admin");
        assert_eq!(format!("{}", TenantRole::Member), "member");
    }

    #[test]
    fn only_admins_and_owners_can_invite_or_revoke() {
        assert!(!TenantRole::Member.can_invite());
        assert!(TenantRole::Admin.can_invite());
        assert!(TenantRole::Owner.can_invite());

        assert!(!TenantRole::Member.can_revoke());
        assert!(TenantRole::Admin.can_revoke());
        assert!(TenantRole::Owner.can_revoke());
    }

    #[test]
    fn privilege_ordering_is_member_admin_owner() {
        assert!(TenantRole::Owner.outranks(TenantRole::Admin));
        assert!(TenantRole::Owner.outranks(TenantRole::Member));
        assert!(TenantRole::Admin.outranks(TenantRole::Member));

        assert!(!TenantRole::Admin.outranks(TenantRole::Owner));
        assert!(!TenantRole::Member.outranks(TenantRole::Admin));
        // Nobody outranks a peer.
        for &role in TenantRole::ALL {
            assert!(!role.outranks(role));
        }
    }

    #[test]
    fn serde_uses_the_same_lowercase_spelling_as_storage() {
        for &role in TenantRole::ALL {
            let json = serde_json::to_string(&role).unwrap();
            assert_eq!(json, format!("\"{}\"", role.as_str()));
            let back: TenantRole = serde_json::from_str(&json).unwrap();
            assert_eq!(back, role);
        }
    }

    #[test]
    fn serde_rejects_an_unknown_role() {
        assert!(serde_json::from_str::<TenantRole>(r#""superuser""#).is_err());
    }

    #[test]
    fn unknown_role_error_names_the_offending_value() {
        let e = TenantRole::parse("wat").unwrap_err();
        assert!(e.to_string().contains("wat"));
    }
}
