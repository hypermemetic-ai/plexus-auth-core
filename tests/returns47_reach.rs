//! RETURNS-47 · what a child needs to receive auth.
//!
//! - `Reach::nowhere()`: the reach of a call made for no one (a child under
//!   the `anonymous` forward policy): it covers and allows nothing.
//!
//! There is no public constructor of a reach from a list of scopes: a reach
//! that names a grant is a gate's answer (plexus-core's child seam builds a
//! hop's ceiling as a gate of the hop alone answers it).
//!
//! (`identity_only` keeping the caller's principal is `auth.rs`'s unit test
//! `identity_only_keeps_the_callers_principal_stamp`: the stamp is crate-private.)

use plexus_auth_core::grants::{Reach, ScopeRef};

#[test]
fn nowhere_covers_and_allows_nothing() {
    let r = Reach::nowhere();
    assert!(r.is_empty());
    assert!(!r.is_everywhere());
    assert!(!r.covers(&[ScopeRef::Everywhere]));
    assert!(!r.allows("MENGER-1"));
    assert_eq!(r.grant(), None);
}
