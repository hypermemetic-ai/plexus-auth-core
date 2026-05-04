//! AUTHZ-CORE-CRATE-1 §"Required behavior" — ServiceIdentity carries the
//! service-id payload of `Principal::Service(_)`. Its constructor is
//! `pub(crate)`; field is private. External construction is rejected.

use plexus_auth_core::ServiceIdentity;

fn main() {
    let _ = ServiceIdentity::new_sealed("plexus.example".into());
}
