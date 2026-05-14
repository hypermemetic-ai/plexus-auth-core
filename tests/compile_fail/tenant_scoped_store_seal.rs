//! AUTHZ-DATA-1-WRAPPER §"Acceptance criteria" item 4 — a sibling crate
//! cannot implement `TenantScopedStore` for its own type. The trait's
//! super-trait `seal::SealedStore` lives in a `pub(crate)` module inside
//! `plexus-auth-core`; third-party crates cannot name it and therefore
//! cannot satisfy the super-trait bound.
//!
//! Diagnostic: the error names the unsatisfied `SealedStore` super-trait
//! bound, confirming the seal works as intended.

use plexus_auth_core::TenantScopedStore;

struct MyStore;

impl TenantScopedStore for MyStore {
    type Error = std::io::Error;
}

fn main() {}
