//! AUTHZ-CORE-CRATE-1 §"Required behavior" — VerifiedUser fields are
//! private; even if a caller had a value in hand, it cannot fabricate one
//! by struct literal.

use plexus_auth_core::VerifiedUser;

fn main() {
    // Attempt: build via struct literal. Fields are private to plexus-auth-core.
    let _ = VerifiedUser {
        user_id: "alice".to_string(),
        issuer: "x".to_string(),
        issued_at: 0,
        expires_at: 0,
    };
}
