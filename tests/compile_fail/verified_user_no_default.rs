//! AUTHZ-CORE-CRATE-1 acceptance criterion 7 — VerifiedUser does NOT
//! implement Default. A default would be anonymous-with-no-claims, easy
//! to confuse with verified-anonymous in security-relevant code.

use plexus_auth_core::VerifiedUser;

fn main() {
    let _: VerifiedUser = Default::default();
}
