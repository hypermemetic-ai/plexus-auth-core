//! `Principal` — sealed authenticated-actor identity.
//!
//! A `Principal` is an authenticated actor: a user, a service, or anonymous.
//! Every cross-boundary invocation has exactly one immediate-caller principal
//! that the framework auto-stamps. Activations receive a `&Principal`; they
//! cannot construct one.
//!
//! Per AUTHZ-0 §"The sealed-type pattern" (and the same protections enumerated
//! in `verified_user.rs`):
//!
//! - **No fabrication.** Constructors are crate-private.
//! - **No backdoor `From` / `Into`.** Orphan rules forbid foreign-trait
//!   impls for this foreign type from a third crate.
//! - **No accidental `Default`.** Not derived; a default would be ambiguous
//!   between anonymous and verified-anonymous.
//! - **No leaky `Deserialize`.** Not derived; raw JSON cannot fabricate one.
//! - **No mutation.** Fields are private; only accessors expose data.

use crate::verified_user::VerifiedUser;
use serde::Serialize;

/// Service-identity claim, paired with `Principal::Service` to identify a
/// non-user authenticated actor (e.g., another Plexus deployment).
#[derive(Debug, Clone, Serialize)]
pub struct ServiceIdentity {
    service_id: String,
}

impl ServiceIdentity {
    /// Mint a `ServiceIdentity`. Crate-private — only the framework's
    /// verifier code (inside `plexus-auth-core`) is able to produce one.
    ///
    /// `dead_code` is allowed for the same reason as
    /// [`VerifiedUser::new_sealed`]: the verifier-side caller lands in a
    /// follow-up ticket. The constructor must exist now for the trybuild
    /// compile-fail asserts to be meaningful.
    #[allow(dead_code)]
    pub(crate) fn new_sealed(service_id: String) -> Self {
        Self { service_id }
    }

    /// The service identifier (e.g., a SPIFFE ID or workload name).
    pub fn service_id(&self) -> &str {
        &self.service_id
    }
}

/// An authenticated actor: a user, a service, or anonymous.
///
/// Every cross-boundary invocation carries exactly one immediate-caller
/// `Principal`. The framework stamps it; activations read it; nobody outside
/// `plexus-auth-core` can construct one.
///
/// # Sealing
///
/// The discriminants below carry sealed payloads (`VerifiedUser`,
/// `ServiceIdentity`), and the `Anonymous` variant is constructable only via
/// the `pub(crate)` `anonymous_sealed` constructor. This means external
/// crates cannot match-then-rebuild a `Principal::Anonymous` and pass it
/// off as authentic; the only way to obtain any `Principal` is through the
/// framework's mint paths inside this crate.
///
/// `tests/compile_fail/seal_principal_construct.rs` asserts external
/// construction is rejected.
#[derive(Debug, Clone, Serialize)]
pub enum Principal {
    /// An end-user principal, carrying the verified token claims.
    User(VerifiedUser),
    /// A non-user authenticated principal (e.g., another Plexus service).
    Service(ServiceIdentity),
    /// An unauthenticated caller. Methods marked `#[plexus::method(public)]`
    /// see this; everything else is denied at the perimeter.
    Anonymous,
}

impl Principal {
    /// Mint the anonymous principal. Crate-private — exists so no external
    /// crate can construct *any* `Principal` variant directly.
    ///
    /// `dead_code` is allowed because the framework code that mints
    /// principals lives in plexus-transport and lands in a follow-up
    /// ticket. The constructor must exist now for the trybuild
    /// compile-fail asserts to be meaningful.
    #[allow(dead_code)]
    pub(crate) fn anonymous_sealed() -> Self {
        Self::Anonymous
    }

    /// Mint a `Principal::User` from a `VerifiedUser`. Crate-private.
    #[allow(dead_code)]
    pub(crate) fn user_sealed(verified: VerifiedUser) -> Self {
        Self::User(verified)
    }

    /// Mint a `Principal::Service` from a `ServiceIdentity`. Crate-private.
    #[allow(dead_code)]
    pub(crate) fn service_sealed(service: ServiceIdentity) -> Self {
        Self::Service(service)
    }

    /// Is this principal a verified user?
    pub fn is_user(&self) -> bool {
        matches!(self, Self::User(_))
    }

    /// Is this principal anonymous?
    pub fn is_anonymous(&self) -> bool {
        matches!(self, Self::Anonymous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_anonymous_constructs() {
        let p = Principal::anonymous_sealed();
        assert!(p.is_anonymous());
        assert!(!p.is_user());
    }

    #[test]
    fn principal_user_carries_verified() {
        let v = VerifiedUser::new_sealed(
            "alice".to_string(),
            "https://idp.example.com".to_string(),
            1_700_000_000,
            1_700_003_600,
        );
        let p = Principal::user_sealed(v);
        assert!(p.is_user());
        match p {
            Principal::User(v) => assert_eq!(v.user_id(), "alice"),
            _ => unreachable!("expected User variant"),
        }
    }

    #[test]
    fn principal_service_carries_identity() {
        let s = ServiceIdentity::new_sealed("plexus.example".to_string());
        let p = Principal::service_sealed(s);
        match p {
            Principal::Service(s) => assert_eq!(s.service_id(), "plexus.example"),
            _ => unreachable!("expected Service variant"),
        }
    }
}
