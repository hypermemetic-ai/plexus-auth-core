//! BIDIR-8: the grants generation is the gate's. Every write that could
//! change an answer moves it once — a grant, a revoke, a role edit, a team
//! add or remove, a sign-out — and a read moves nothing. A duplex call (and
//! a menger watch) compares it to decide when to ask the gate again.

use std::sync::Arc;

use plexus_auth_core::grants::{Gate, GrantsGeneration, GrantsMove, Membership, Memberships, Resolve, RoleTable, ScopeRef};
use plexus_auth_core::identity::Principal;
use plexus_auth_core::{AuthContext, RoleName};
use serde_json::Value;

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct One;
impl Memberships for One {
    fn held(&self, who: &Principal) -> Vec<Membership> {
        vec![Membership { principal: who.clone(), role: RoleName::new("editor"), scope: ScopeRef::Everywhere }]
    }
}
struct Anywhere;
impl Resolve for Anywhere {
    fn chain(&self, _: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

fn gate() -> Gate {
    let roles = RoleTable::new().define("editor", ["runs.append_log"]).unwrap();
    Gate::new(Arc::new(One), Arc::new(roles), Arc::new(Anywhere))
}

#[test]
fn every_grant_write_moves_the_generation() {
    let g = gate();
    assert_eq!(g.generation().current(), 0, "a new gate starts at 0");
    let moves = [GrantsMove::Grant, GrantsMove::Revoke, GrantsMove::RoleEdit, GrantsMove::TeamAdd, GrantsMove::TeamRemove, GrantsMove::SignOut];
    for (i, m) in moves.into_iter().enumerate() {
        let now = g.moved(m);
        assert_eq!(now, i as u64 + 1, "{m:?}: +1");
        assert_eq!(g.generation().current(), now);
    }
    // A read moves nothing.
    let ada = AuthContext::for_principal(&ADA.parse().unwrap(), "s", vec![], Value::Null);
    let before = g.generation().current();
    for _ in 0..10 {
        g.check(Some(&ada), &plexus_auth_core::grants::Grant::new("runs.append_log"), Some("X-1")).unwrap();
        let _ = g.held_on(&ada, &plexus_auth_core::grants::Grant::new("runs.append_log"));
    }
    assert_eq!(g.generation().current(), before, "a read: 0");
}

#[test]
fn a_service_shares_one_generation_between_its_gates() {
    // menger: the service's call gate and the access layer's gate are two `Gate`s
    // over one book; one handle makes them one generation.
    let shared = GrantsGeneration::new();
    let a = gate().with_generation(shared.clone());
    let b = gate().with_generation(shared.clone());
    a.moved(GrantsMove::Revoke);
    assert_eq!(b.generation().current(), 1);
    shared.bump();
    assert_eq!(a.generation().current(), 2);
    // A clone of the gate keeps it; so does `with_liveness`.
    struct Live;
    impl plexus_auth_core::grants::Liveness for Live {
        fn alive(&self, _: &AuthContext) -> Result<(), String> {
            Ok(())
        }
    }
    let c = a.clone().with_liveness(Arc::new(Live));
    c.moved(GrantsMove::SignOut);
    assert_eq!(shared.current(), 3);
}

#[tokio::test]
async fn a_move_wakes_whoever_watches_it() {
    let g = gate();
    let mut rx = g.generation().subscribe();
    let seen = *rx.borrow_and_update();
    g.moved(GrantsMove::Grant);
    tokio::time::timeout(std::time::Duration::from_millis(50), rx.changed()).await.expect("woken").unwrap();
    assert_eq!(*rx.borrow(), seen + 1);
}

#[test]
fn a_count_carried_over_never_goes_back() {
    // A service that counted before it shared the gate's handle carries its
    // count over (menger's store at attach): forward only.
    let g = GrantsGeneration::new();
    g.raise_to(57);
    assert_eq!(g.current(), 57);
    g.raise_to(3);
    assert_eq!(g.current(), 57, "never back");
    g.bump();
    assert_eq!(g.current(), 58);
}
