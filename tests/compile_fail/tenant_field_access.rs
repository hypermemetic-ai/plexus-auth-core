//! AUTHZ-DATA-1-TYPES §"Required behavior" — the value carrier is a
//! validated owned string, not exposed as a public field. A sibling
//! crate that tries to construct a `Tenant` via struct-literal syntax
//! (`Tenant("alice".into())`) must fail to compile: the inner field is
//! private to `plexus-auth-core`.

use plexus_auth_core::Tenant;

fn main() {
    // Attempt: bypass the sealed constructor via the tuple-struct field.
    let _ = Tenant("victim-tenant".to_string());
}
