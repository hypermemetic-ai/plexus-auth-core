//! FRAME-5: `Reach::recheck` is `Reach::current` with the gate's refusal
//! kept, so a held open call (the ui service's watch) can say why it ends:
//! a sign-in that no longer stands is `Ended`, grants that moved away are
//! `MissingGrant`; while both stand it answers the reach, as `current` does.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use plexus_auth_core::grants::{Gate, Grant, Liveness, Membership, Memberships, Reach, Refusal, Resolve, RoleTable, ScopeRef};
use plexus_auth_core::identity::Principal;
use plexus_auth_core::{AuthContext, RoleName};
use serde_json::Value;

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Ada is a viewer everywhere while `held`.
struct Held(Arc<AtomicBool>);
impl Memberships for Held {
    fn held(&self, who: &Principal) -> Vec<Membership> {
        match self.0.load(Ordering::SeqCst) {
            true => vec![Membership { principal: who.clone(), role: RoleName::new("viewer"), scope: ScopeRef::Everywhere }],
            false => vec![],
        }
    }
}

/// The sign-in stands while `alive`.
struct Alive(Arc<AtomicBool>);
impl Liveness for Alive {
    fn alive(&self, _: &AuthContext) -> Result<(), String> {
        match self.0.load(Ordering::SeqCst) {
            true => Ok(()),
            false => Err("you have signed out: sign in again".into()),
        }
    }
}

struct Anywhere;
impl Resolve for Anywhere {
    fn chain(&self, _: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

#[test]
fn recheck_keeps_the_refusal_current_drops() {
    let (held, alive) = (Arc::new(AtomicBool::new(true)), Arc::new(AtomicBool::new(true)));
    let roles = RoleTable::new().define("viewer", ["ui.watch"]).unwrap();
    let gate = Gate::new(Arc::new(Held(held.clone())), Arc::new(roles), Arc::new(Anywhere)).with_liveness(Arc::new(Alive(alive.clone())));
    let ada = AuthContext::for_principal(&ADA.parse().unwrap(), "s", vec![], Value::Null);
    let reach = gate.check(Some(&ada), &Grant::new("ui.watch"), None).expect("a viewer holds ui.watch");

    // Both stand: the reach, as current answers it.
    assert_eq!(reach.recheck().ok(), reach.current(), "standing: the same reach");
    assert!(reach.recheck().is_ok());

    // The grants moved away: MissingGrant, naming the grant.
    held.store(false, Ordering::SeqCst);
    assert!(reach.current().is_none());
    match reach.recheck() {
        Err(Refusal::MissingGrant { grant, .. }) => assert_eq!(grant.as_str(), "ui.watch"),
        other => panic!("revoked: {other:?}"),
    }

    // The sign-in ended (whatever it holds): Ended, with the liveness's words.
    held.store(true, Ordering::SeqCst);
    alive.store(false, Ordering::SeqCst);
    assert!(reach.current().is_none());
    match reach.recheck() {
        Err(Refusal::Ended { reason }) => assert!(reason.contains("signed out"), "{reason}"),
        other => panic!("signed out: {other:?}"),
    }
}

#[test]
fn without_a_gate_recheck_is_the_reach() {
    let everywhere = Reach::everywhere();
    assert_eq!(everywhere.recheck().ok(), Some(Reach::everywhere()));
}
