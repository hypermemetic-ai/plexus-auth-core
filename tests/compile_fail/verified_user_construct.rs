//! AUTHZ-CORE-CRATE-1 §"Required behavior" — VerifiedUser cannot be
//! constructed by any external crate. The `pub(crate)` constructor and
//! private fields together make this fail to compile.

use plexus_auth_core::VerifiedUser;

fn main() {
    // Attempt 1: call the (sealed) constructor.
    let _ = VerifiedUser::new_sealed(
        "alice".to_string(),
        "https://idp.example.com".to_string(),
        0,
        0,
    );
}
