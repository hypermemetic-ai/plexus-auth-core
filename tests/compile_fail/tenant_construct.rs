//! AUTHZ-DATA-1-TYPES §"Acceptance criteria" item 5 — a sibling crate
//! cannot construct a `Tenant` directly. `Tenant::try_new` is `pub(crate)`
//! to `plexus-auth-core`; the only path to a `Tenant` value is through
//! the framework's `TenantResolver`, which derives one from a verified
//! `AuthContext`. This trybuild program asserts the constructor is
//! unreachable from outside the crate (compile-fail is the structural
//! defense).

use plexus_auth_core::Tenant;

fn main() {
    // Attempt: call the (sealed) constructor.
    let _ = Tenant::try_new("victim-tenant");
}
