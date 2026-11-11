//! ONE-6: a role held on an address. `/dyn` is dyn's own methods (and
//! `/dyn.connect` that one method); `/dyn.*` is dyn and everything mounted
//! under it; `self` is `*`, the service being called.
//!
//! Activation scopes and data scopes are separate (owner, 2026-11-11): an
//! address scope opens the door of the calls it covers — a whole-service
//! method, a call into a peer — and never stands for data.

use std::sync::{Arc, Mutex};

use plexus_auth_core::grants::{
    CallAddress, DispatchedCall, Gate, Grant, Membership, Memberships, Reach, Refusal, Resolve, RoleTable, ScopeRef,
    CEILING_KEY,
};
use plexus_auth_core::identity::Principal;
use plexus_auth_core::{AuthContext, RoleName};

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// --- the world --------------------------------------------------------------

/// What each role lists. A dialed peer is an untyped slot: its grant is
/// `dyn.{peer}` whichever peer is called.
fn roles() -> RoleTable {
    RoleTable::new()
        .define("viewer", ["tickets.get", "tickets.list"])
        .unwrap()
        .define("operator", ["viewer", "dyn.connect", "dyn.disconnect", "dyn.{peer}", "ui.push"])
        .unwrap()
}

/// The grant a call needs, as plexus-core names it.
fn grant_of(path: &str) -> Grant {
    match path.starts_with("dyn.peer.") {
        true => Grant::new("dyn.{peer}"),
        false => Grant::new(path),
    }
}

/// A call's address, told apart at its last dot as dispatch tells it.
fn at(path: &str) -> CallAddress {
    let (activation, method) = path.rsplit_once('.').unwrap();
    CallAddress::new(activation, method).unwrap()
}

/// The call to `path` as dispatch hands it to the gate: its address and
/// its grant, paired once.
fn call(path: &str) -> DispatchedCall {
    DispatchedCall::new(at(path), grant_of(path))
}

/// Tickets `CODE-n` live in `CODE`; nothing else resolves.
struct Shortcodes;
impl Resolve for Shortcodes {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        let (code, _) = target.split_once('-')?;
        Some(vec![ScopeRef::named(target), ScopeRef::named(code), ScopeRef::Everywhere])
    }
}

/// A resolver that tries to forge: every chain it answers names an address.
struct Forger;
impl Resolve for Forger {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::named(target), ScopeRef::named("/ui.*"), ScopeRef::named("/dyn"), ScopeRef::Everywhere])
    }
}

struct Held(Mutex<Vec<Membership>>);
impl Memberships for Held {
    fn held(&self, who: &Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}

/// Ada, holding what she is given, asked about by the gate.
struct Ada {
    gate: Gate,
    held: Arc<Held>,
    session: AuthContext,
}

/// Ada holds each `"role on SCOPE"`, the scope as a grant would write it.
fn ada(holds: &[&str]) -> Ada {
    ada_with(holds, Arc::new(Shortcodes))
}

fn ada_with(holds: &[&str], resolve: Arc<dyn Resolve>) -> Ada {
    let held = holds
        .iter()
        .map(|h| {
            let (role, scope) = h.split_once(" on ").unwrap();
            membership(role, ScopeRef::parse_checked(scope).unwrap())
        })
        .collect();
    let held = Arc::new(Held(Mutex::new(held)));
    let gate = Gate::new(held.clone(), Arc::new(roles()), resolve);
    let session = AuthContext::for_principal(&ADA.parse().unwrap(), "s", vec![], serde_json::Value::Null);
    Ada { gate, held, session }
}

fn membership(role: &str, scope: ScopeRef) -> Membership {
    Membership { principal: ADA.parse().unwrap(), role: RoleName::new(role), scope }
}

impl Ada {
    /// …her session capped to these `role@SCOPE` entries.
    fn capped_to(mut self, ceiling: &[&str]) -> Self {
        let meta = serde_json::json!({ CEILING_KEY: ceiling });
        self.session = AuthContext::for_principal(&ADA.parse().unwrap(), "s", vec![], meta);
        self
    }

    /// …and a scope written raw, as a store might hold it unchecked.
    fn also_holds_raw(self, role: &str, scope: &str) -> Self {
        self.held.0.lock().unwrap().push(membership(role, ScopeRef::named(scope)));
        self
    }

    /// At the door: may she make this whole-service call, or this call
    /// into a peer?
    fn may(&self, path: &str) -> bool {
        self.door(path).is_ok()
    }

    fn door(&self, path: &str) -> Result<Reach, Refusal> {
        self.gate.check_everywhere_at(Some(&self.session), &call(path))
    }

    /// May she read this ticket?
    fn reads(&self, ticket: &str) -> bool {
        self.gate.check(Some(&self.session), &Grant::new("tickets.get"), Some(ticket)).is_ok()
    }

    /// What a ticket list answers her from — `None` when it is refused.
    fn lists_from(&self) -> Option<Vec<ScopeRef>> {
        self.gate.check(Some(&self.session), &Grant::new("tickets.list"), None).ok().map(|r| r.held_on().to_vec())
    }

    /// Inside a call, may she use another grant — a second check, a seam,
    /// a store's sub-check, which is told no call?
    fn may_also(&self, grant: &str) -> bool {
        self.gate.check(Some(&self.session), &Grant::new(grant), None).is_ok()
            || self.gate.check_everywhere(Some(&self.session), &Grant::new(grant)).is_ok()
    }

    /// Is the grant "held anywhere"?
    fn holds_anywhere(&self, grant: &str) -> bool {
        !self.gate.held_on(&self.session, &Grant::new(grant)).is_empty()
    }

    fn loses_everything(&self) {
        self.held.0.lock().unwrap().clear();
    }
}

fn kiln() -> Vec<ScopeRef> {
    vec![ScopeRef::named("KILN")]
}

// --- the door: what each address opens -----------------------------------------

#[test]
fn an_operator_on_dyn_may_connect_but_not_call_into_a_peer() {
    let ada = ada(&["operator on /dyn"]);
    assert!(ada.may("dyn.connect"));
    assert!(ada.may("dyn.disconnect"));
    assert!(!ada.may("dyn.peer.shop.items.list"));
}

#[test]
fn an_operator_on_one_method_may_call_that_method_alone() {
    let ada = ada(&["operator on /dyn.connect"]);
    assert!(ada.may("dyn.connect"));
    assert!(!ada.may("dyn.disconnect"));
}

#[test]
fn an_operator_on_all_of_dyn_may_connect_and_call_into_any_peer() {
    let ada = ada(&["operator on /dyn.*"]);
    assert!(ada.may("dyn.connect"));
    assert!(ada.may("dyn.peer.shop.items.list"));
    assert!(ada.may("dyn.peer.bank.accounts.list"));
}

#[test]
fn an_operator_on_one_peer_reaches_that_peer_alone() {
    let ada = ada(&["operator on /dyn.peer.shop.*"]);
    assert!(ada.may("dyn.peer.shop.items.list"));
    assert!(ada.may("dyn.peer.shop.health"));
    assert!(!ada.may("dyn.peer.bank.accounts.list"));
    assert!(!ada.may("dyn.peer.shopx.items.list"));
    assert!(!ada.may("dyn.connect"));
}

#[test]
fn an_operator_on_ui_may_neither_connect_nor_call_a_peer() {
    let ada = ada(&["operator on /ui"]);
    assert!(ada.may("ui.push"));
    assert!(!ada.may("dyn.connect"));
    assert!(!ada.may("dyn.peer.shop.items.list"));
}

#[test]
fn a_whole_service_method_is_held_on_its_own_address_or_above() {
    for scope in ["*", "self", "/dyn", "/dyn.connect", "/dyn.*"] {
        assert!(ada(&[&format!("operator on {scope}")]).may("dyn.connect"), "operator on {scope}");
    }
    for scope in ["/ui", "/ui.*", "/dyn.peer.*", "/dyn.peer.shop.*", "/dyn.disconnect", "/dynamo", "KILN"] {
        assert!(!ada(&[&format!("operator on {scope}")]).may("dyn.connect"), "operator on {scope}");
    }
}

#[test]
fn an_admin_on_a_data_scope_is_still_refused_a_whole_service_method() {
    let ada = ada(&["admin on KILN", "admin on KILN-1"]);
    assert!(ada.reads("KILN-1"));
    match ada.door("dyn.connect") {
        Err(Refusal::MissingGrant { scope, held_on, .. }) => {
            assert_eq!(scope, ScopeRef::named("/dyn"), "the refusal names the activation");
            assert_eq!(held_on, [ScopeRef::named("KILN"), ScopeRef::named("KILN-1")]);
        }
        other => panic!("admin on KILN: {other:?}"),
    }
    assert!(ada.gate.check_everywhere(Some(&ada.session), &Grant::new("dyn.connect")).is_err());
}

#[test]
fn self_is_the_service_being_called() {
    assert_eq!(ScopeRef::parse_checked("self"), Ok(ScopeRef::Everywhere));
    let ada = ada(&["operator on self"]);
    assert!(ada.may("dyn.connect") && ada.may("dyn.peer.shop.items.list"));
    assert!(ada.reads("KILN-1"));
    assert_eq!(ada.lists_from(), Some(vec![ScopeRef::Everywhere]));
}

// --- an address never stands for data (owner, 2026-11-11) ---------------------

#[test]
fn a_viewer_on_tickets_reads_no_organizations_tickets() {
    let ada = ada(&["viewer on /tickets.*"]);
    assert!(!ada.reads("OTHERORG-1"));
    assert!(!ada.reads("KILN-1"));
    assert_eq!(ada.lists_from(), None, "a list is refused, never all organizations");
    assert!(!ada.holds_anywhere("tickets.list"));
}

#[test]
fn a_viewer_on_tickets_and_on_kiln_reads_kiln_alone() {
    let ada = ada(&["viewer on /tickets.*", "viewer on KILN"]);
    assert!(ada.reads("KILN-1"));
    assert!(!ada.reads("OTHERORG-1"));
    assert_eq!(ada.lists_from(), Some(kiln()));
}

#[test]
fn an_operator_on_ui_holds_no_read_anywhere() {
    let ada = ada(&["operator on /ui"]);
    assert!(!ada.reads("KILN-1"));
    assert_eq!(ada.lists_from(), None);
    assert!(!ada.holds_anywhere("tickets.list"));
}

// --- what a door's reach says -------------------------------------------------

#[test]
fn a_reach_through_the_door_holds_the_activation_and_no_data() {
    let ada = ada(&["operator on /dyn"]);
    let reach = ada.door("dyn.connect").unwrap();
    assert!(reach.holds_activation());
    assert!(!reach.is_everywhere(), "an address is not `*`");
    assert!(reach.held_on().is_empty());
    assert!(!reach.allows("KILN-1"));
}

#[test]
fn a_reach_through_the_door_holds_only_the_data_scopes_held() {
    let ada = ada(&["operator on /dyn", "operator on KILN"]);
    let reach = ada.door("dyn.connect").unwrap();
    assert!(reach.holds_activation() && !reach.is_everywhere());
    assert_eq!(reach.held_on(), kiln());
    assert!(reach.allows("KILN-1"));
    assert!(!reach.allows("OTHERORG-1"));
}

#[test]
fn an_admin_everywhere_holds_the_activation_and_all_data() {
    let reach = ada(&["admin on *"]).door("dyn.connect").unwrap();
    assert!(reach.holds_activation() && reach.is_everywhere());
    assert!(reach.allows("OTHERORG-1"));
}

#[test]
fn a_data_reach_never_holds_an_activation() {
    let ada = ada(&["viewer on KILN"]);
    let reach = ada.gate.check(Some(&ada.session), &Grant::new("tickets.list"), None).unwrap();
    assert!(!reach.holds_activation());
    assert!(Reach::everywhere().holds_activation(), "without a gate, everything");
    assert!(!Reach::nowhere().holds_activation());
}

#[test]
fn a_reach_through_the_door_ends_when_the_membership_does() {
    let ada = ada(&["operator on /dyn.*"]);
    let reach = ada.door("dyn.peer.shop.items.list").unwrap();
    assert!(reach.current().is_some_and(|r| r.holds_activation()));
    ada.loses_everything();
    assert!(reach.current().is_none());
    assert!(reach.recheck().is_err());
}

// --- ceilings ----------------------------------------------------------------------

#[test]
fn a_session_capped_to_an_address_opens_that_door_alone_and_reads_nothing() {
    let ada = ada(&["admin on *"]).capped_to(&["admin@/dyn"]);
    assert!(ada.may("dyn.connect"));
    assert!(!ada.may("dyn.peer.shop.items.list"));
    assert!(!ada.reads("KILN-1"));
    assert_eq!(ada.lists_from(), None);
}

#[test]
fn a_session_capped_to_a_data_scope_opens_no_door() {
    let ada = ada(&["operator on /dyn.*", "operator on *"]).capped_to(&["operator@KILN"]);
    assert!(!ada.may("dyn.connect"));
    assert!(ada.reads("KILN-1"));
    assert!(!ada.reads("OTHERORG-1"));
}

#[test]
fn a_ceiling_still_narrows_the_data_beside_an_address() {
    let ada = ada(&["viewer on /tickets.*", "viewer on *"]).capped_to(&["viewer@KILN"]);
    assert!(ada.reads("KILN-1"));
    assert!(!ada.reads("OTHERORG-1"));
    assert_eq!(ada.lists_from(), Some(kiln()));
}

#[test]
fn a_ceiling_on_an_address_never_widens() {
    let ada = ada(&["operator on /ui"]).capped_to(&["operator@/dyn.*"]);
    assert!(!ada.may("dyn.connect"));
    assert!(!ada.may("ui.push"));
}

#[test]
fn a_ceiling_naming_one_grant_on_an_address_allows_that_grant_there() {
    let ada = ada(&["admin on *"]).capped_to(&["dyn.connect@/dyn"]);
    assert!(ada.may("dyn.connect"));
    assert!(!ada.may("dyn.disconnect"));
}

// --- the grant is tied to the address (review F1) ----------------------------

#[test]
fn an_operator_on_one_method_holds_no_other_grant_inside_that_call() {
    let ada = ada(&["operator on /dyn.connect"]);
    assert!(ada.may("dyn.connect"));
    assert!(!ada.may_also("dyn.disconnect"));
}

#[test]
fn an_admin_on_dyn_cannot_grant_roles_from_inside_connect() {
    let ada = ada(&["admin on /dyn"]);
    assert!(ada.may("dyn.connect"));
    assert!(!ada.may_also("auth.grant"));
}

// --- one spelling for the root (review F3) -----------------------------------

#[test]
fn self_stored_raw_holds_nothing_anywhere() {
    for raw in [ScopeRef::parse("self"), serde_json::from_str::<ScopeRef>("\"self\"").unwrap()] {
        assert_eq!(raw, ScopeRef::named("self"), "the lenient spelling is a name");
        let ada = ada(&[]).also_holds_raw("admin", raw.as_str());
        assert!(!ada.may("dyn.connect"));
        assert!(!ada.reads("KILN-1"));
        assert!(!ada.holds_anywhere("tickets.list"));
        assert!(!ada.may_also("auth.grant"));
    }
}

#[test]
fn a_ceiling_of_self_stored_raw_allows_nothing() {
    let ada = ada(&["admin on *"]).capped_to(&["admin@self"]);
    assert!(!ada.may("dyn.connect"));
    assert!(!ada.reads("KILN-1"));
    assert!(!ada.holds_anywhere("tickets.list"));
}

#[test]
fn a_resolver_cannot_name_self_in_a_chain() {
    struct Selfish;
    impl Resolve for Selfish {
        fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
            Some(vec![ScopeRef::named(target), ScopeRef::named("self")])
        }
    }
    let ada = ada_with(&[], Arc::new(Selfish)).also_holds_raw("viewer", "self");
    assert!(!ada.reads("KILN-1"));
}

// --- look-alikes ---------------------------------------------------------------

#[test]
fn malformed_address_scopes_are_refused() {
    for text in [
        "/", "//", "/*", "/.*", "/dyn.", "/.dyn", "/dyn..peer", "/dyn.*.x", "/dyn.*.*", "/dyn**", "/d*n",
        "/dyn@KILN", "/dyn peer", "/dyn\t", " /dyn", "/dyn ", "/dÿn", "/dyn/peer", "/dyn.{peer}", "",
    ] {
        assert!(ScopeRef::parse_checked(text).is_err(), "{text:?} must be refused");
    }
    for text in ["/dyn", "/dyn.*", "/dyn.peer.shop.*", "/dyn.connect", "/my-shop_2", "*", "KILN", "under KILN-1"] {
        assert!(ScopeRef::parse_checked(text).is_ok(), "{text:?} must be taken");
    }
}

#[test]
fn look_alike_addresses_cover_nothing_they_resemble() {
    assert!(!ada(&["operator on /dynamo"]).may("dyn.connect"));
    assert!(!ada(&["operator on /dyn.*"]).may("dynamo.connect"));
    assert!(!ada(&["operator on /dyn.peer.*"]).may("dyn.peerx.shop.list"));
    assert!(!ada(&["operator on /DYN"]).may("dyn.connect"));
    assert!(!ada(&["operator on /Dyn.*"]).may("dyn.connect"));
}

#[test]
fn a_malformed_address_held_raw_holds_nothing() {
    for raw in ["/dyn.", "//", "/*", "/dyn.*.x", "/", "/dyn@x", "/ dyn", "/dyn.connect "] {
        let ada = ada(&[]).also_holds_raw("admin", raw);
        assert!(!ada.may("dyn.connect"), "{raw:?}");
        assert!(!ada.reads("KILN-1"), "{raw:?}");
        assert!(!ada.holds_anywhere("tickets.list"), "{raw:?}");
    }
}

// --- the dispatcher's contract (review F5, F6) --------------------------------

#[test]
fn a_call_address_splits_only_at_its_method() {
    assert!(CallAddress::new("dyn", "peer.shop").is_err(), "a method is one segment");
    assert!(CallAddress::new("dyn", "").is_err());
    assert!(CallAddress::new("", "connect").is_err());
    assert!(CallAddress::new("dyn.", "connect").is_err());
    assert!(CallAddress::new("dyn", "con nect").is_err());
    let shop = CallAddress::new("dyn.peer.shop.items", "list").unwrap();
    assert_eq!((shop.activation(), shop.method(), shop.path()), ("dyn.peer.shop.items", "list", "dyn.peer.shop.items.list"));
}

#[test]
fn a_key_holding_a_dot_is_never_one_segment() {
    assert!(CallAddress::new("dyn.peer.github.repos.alice", "app.v2").is_err());
    assert!(CallAddress::of_segments(&["dyn", "peer", "github", "repos", "alice", "app.v2"], "issues").is_err());
    assert!(CallAddress::of_segments(&[], "list").is_err());
    let routed = CallAddress::of_segments(&["dyn", "peer", "github", "repos", "alice", "app"], "issues").unwrap();
    assert_eq!(routed, CallAddress::new("dyn.peer.github.repos.alice.app", "issues").unwrap());
    // Joined by hand, a dotted key cannot be told from two segments: hence `of_segments`.
    assert!(CallAddress::new("dyn.peer.github.repos.alice.app.v2", "issues").is_ok());
}

#[test]
fn an_address_names_a_method_and_an_activation_alike() {
    let connect = ScopeRef::parse_checked("/dyn.connect").unwrap();
    assert!(connect.covers_address(&at("dyn.connect")));
    assert!(connect.covers_address(&at("dyn.connect.status")));
    assert!(!connect.covers_address(&at("dyn.connect.status.read")));
}

// --- the gate owns addresses -------------------------------------------------

#[test]
fn a_resolver_cannot_put_an_address_in_a_chain() {
    let ada = ada_with(&["operator on /ui.*", "operator on /dyn"], Arc::new(Forger));
    assert!(!ada.reads("KILN-1"));
    assert!(!ada.reads("/dyn"));
    assert!(!ada.reads("/ui.*"));
}

#[test]
fn a_data_scope_beginning_with_a_slash_is_no_data_scope() {
    // Held raw as if a service had named a data scope `/KILN`, and a
    // resolver that answers it: it is an address, and holds no data.
    struct Slashed;
    impl Resolve for Slashed {
        fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
            Some(vec![ScopeRef::named(target), ScopeRef::named("/KILN"), ScopeRef::Everywhere])
        }
    }
    let ada = ada_with(&[], Arc::new(Slashed)).also_holds_raw("viewer", "/KILN");
    assert!(!ada.reads("KILN-1"));
    assert!(!ada.reads("/KILN"));
    assert!(!ada.holds_anywhere("tickets.list"));
}

#[test]
fn told_no_call_the_gate_holds_an_address_scope_on_nothing() {
    let ada = ada(&["admin on /dyn.*"]);
    assert!(ada.gate.check(Some(&ada.session), &Grant::new("dyn.connect"), None).is_err());
    assert!(ada.gate.check_everywhere(Some(&ada.session), &Grant::new("dyn.connect")).is_err());
    assert!(ada.gate.reach_of_public(Some(&ada.session), &Grant::new("dyn.connect")).is_empty());
    assert!(ada.may("dyn.connect"));
}
