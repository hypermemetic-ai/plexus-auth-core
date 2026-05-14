//! AUTHZ-DATA-1-WRAPPER §"`TenantBoundary` witness" — a sibling crate
//! cannot fabricate a `TenantBoundary` via struct-literal construction:
//! the `_seal` field is module-private.
//!
//! Diagnostic: `field '_seal' of struct 'TenantBoundary' is private`
//! (E0451).

use plexus_auth_core::TenantBoundary;

fn main() {
    let _ = TenantBoundary { _seal: () };
}
