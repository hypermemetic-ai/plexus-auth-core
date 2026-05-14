//! AUTHZ-DATA-1-WRAPPER §"`TenantBoundary` witness" — a sibling crate
//! cannot reach the (sealed) constructor of `TenantBoundary`.
//!
//! Diagnostic: `associated function 'new_sealed' is private` (E0624).
//!
//! Struct-literal fabrication is the subject of a separate compile-fail
//! file (`tenant_boundary_struct_literal.rs`) because rustc aborts after
//! the first error.

use plexus_auth_core::TenantBoundary;

fn main() {
    let _ = TenantBoundary::new_sealed();
}
