//! AUTHZ-CORE-CRATE-1 acceptance criterion 7 — Principal does NOT
//! implement Default. A default would be ambiguous between
//! anonymous-by-omission and verified-anonymous.

use plexus_auth_core::Principal;

fn main() {
    let _: Principal = Default::default();
}
