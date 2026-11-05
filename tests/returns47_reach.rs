//! RETURNS-47 · what a child needs to receive auth.
//!
//! - `Reach::nowhere()`: the reach of a call made for no one (a child under
//!   the `anonymous` forward policy): it covers and allows nothing.
//! - `Reach::from_hop_ceiling(grant, held_on)`: a child's reach for a call
//!   that came through the seam — the near side's verdict, as a ceiling. It
//!   names the grant and covers exactly the scopes held; with no gate behind
//!   it, it allows a target by name only on `*`. Nothing else makes a reach
//!   from a list of scopes.
//!
//! (`identity_only` keeping the caller's principal is `auth.rs`'s unit test
//! `identity_only_keeps_the_callers_principal_stamp`: the stamp is crate-private.)

use plexus_auth_core::grants::{Grant, Reach, ScopeRef};

#[test]
fn nowhere_covers_and_allows_nothing() {
    let r = Reach::nowhere();
    assert!(r.is_empty());
    assert!(!r.is_everywhere());
    assert!(!r.covers(&[ScopeRef::Everywhere]));
    assert!(!r.allows("MENGER-1"));
    assert_eq!(r.grant(), None);
}

#[test]
fn a_hop_ceiling_names_its_grant_and_covers_only_its_scopes() {
    let r = Reach::from_hop_ceiling(Grant::new("forge.repos".to_string()), vec![ScopeRef::named("MENGER")]);
    assert_eq!(r.grant().map(|g| g.as_str()), Some("forge.repos"));
    assert_eq!(r.held_on(), &[ScopeRef::named("MENGER")]);
    assert!(r.covers(&[ScopeRef::named("MENGER"), ScopeRef::Everywhere]));
    assert!(!r.covers(&[ScopeRef::named("OTHER"), ScopeRef::Everywhere]));
    assert!(!r.is_everywhere());
    assert!(!r.allows("MENGER-1"), "no gate to resolve a target: only `*` allows by name");
    let all = Reach::from_hop_ceiling(Grant::new("forge.repos".to_string()), vec![ScopeRef::Everywhere]);
    assert!(all.allows("ANY-1"));
    assert_eq!(all.current(), Some(all.clone()), "no gate behind it to ask again");
}
