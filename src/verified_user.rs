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

use serde::Serialize;

/// Sealed proof that an IdP-signed token was verified.
///
/// Carries the verified claims that the framework extracted from the signed
/// token (`user_id`, `issuer`, `issued_at`, `expires_at`). The presence of a
/// `VerifiedUser` value is itself the proof — there is no way to construct
/// one from outside `plexus-auth-core`.
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
}

impl VerifiedUser {
    /// Mint a new `VerifiedUser`.
    ///
    /// This is `pub(crate)` — only the verifier inside `plexus-auth-core`
    /// can call it. External crates that need to produce a `VerifiedUser`
    /// must route through the (forthcoming) verifier API; they cannot
    /// construct one directly.
    ///
    /// `dead_code` is allowed because the verifier code that consumes this
    /// constructor lands in a follow-up ticket (AUTHZ-FLOWS-DEVIDP-1 / the
    /// JWT verifier work). The constructor itself must exist now so the
    /// trybuild compile-fail tests can assert external crates can't reach
    /// it; suppressing the warning here is preferable to a fake call site.
    #[allow(dead_code)]
    pub(crate) fn new_sealed(
        user_id: String,
        issuer: String,
        issued_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            user_id,
            issuer,
            issued_at,
            expires_at,
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
        );
        assert_eq!(v.user_id(), "alice");
        assert_eq!(v.issuer(), "https://idp.example.com");
        assert_eq!(v.issued_at(), 1_700_000_000);
        assert_eq!(v.expires_at(), 1_700_003_600);
    }
}
