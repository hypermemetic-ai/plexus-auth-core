//! AUTHZ-CORE-CRATE-1 §"Required behavior" — Principal::User wraps a
//! sealed VerifiedUser. Because `VerifiedUser::new_sealed` is `pub(crate)`,
//! external crates cannot mint a User principal even if Principal::User is
//! a public variant.

use plexus_auth_core::{Principal, VerifiedUser};

fn main() {
    // Cannot get a VerifiedUser, so cannot get a Principal::User.
    let v = VerifiedUser::new_sealed("alice".into(), "i".into(), 0, 0, None);
    let _ = Principal::User(v);
}
