//! AUTHZ-CORE-CRATE-1 acceptance criterion 7 — AuthContext does NOT
//! implement Default. The framework provides `AuthContext::anonymous()`
//! as the explicit anonymous constructor; a Default impl would let
//! callers accidentally produce an empty/unauthenticated context where a
//! verified one is required.

use plexus_auth_core::AuthContext;

fn main() {
    let _: AuthContext = Default::default();
}
