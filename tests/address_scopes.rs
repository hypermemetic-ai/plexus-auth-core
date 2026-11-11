//! ONE-6: a role held on an address. `/dyn` is dyn's own methods (and
//! `/dyn.connect` that one method); `/dyn.*` is dyn and everything mounted
//! under it; `self` is `*`, the service being called. An address scope
//! holds a grant only inside a call it covers, and there it reads as `*`.

use std::sync::{Arc, Mutex};

use plexus_auth_core::grants::{
    CallAddress, DispatchedCall, Gate, Grant, Membership, Memberships, Reach, Refusal, Resolve, RoleTable, ScopeRef, CEILING_KEY,
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

    fn reach(&self, path: &str) -> Result<Reach, Refusal> {
        self.gate.check_at(Some(&self.session), &call(path), None)
    }

    /// May she make this call (no target)?
    fn may(&self, path: &str) -> bool {
        self.reach(path).is_ok()
    }

    /// May she make this call on that target?
    fn may_on(&self, path: &str, target: &str) -> bool {
        self.gate.check_at(Some(&self.session), &call(path), Some(target)).is_ok()
    }

    /// May she call this whole-service method?
    fn may_everywhere(&self, path: &str) -> bool {
        self.refused_everywhere(path).is_none()
    }

    fn refused_everywhere(&self, path: &str) -> Option<Refusal> {
        self.gate.check_everywhere_at(Some(&self.session), &call(path)).err()
    }

    /// Inside a call, may she use another grant — a second check, a seam,
    /// a store's sub-check, which is told no address?
    fn may_also(&self, grant: &str) -> bool {
        self.gate.check(Some(&self.session), &Grant::new(grant), None).is_ok()
            || self.gate.check_everywhere(Some(&self.session), &Grant::new(grant)).is_ok()
    }

    /// Is the grant "held anywhere" by the gate's old, addressless word?
    fn holds_anywhere(&self, grant: &str) -> bool {
        !self.gate.held_on(&self.session, &Grant::new(grant)).is_empty()
            || self.gate.check(Some(&self.session), &Grant::new(grant), None).is_ok()
    }

    fn loses_everything(&self) {
        self.held.0.lock().unwrap().clear();
    }
}

// --- what each scope reaches -------------------------------------------------

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
fn an_operator_on_ui_holds_no_read_elsewhere() {
    let ada = ada(&["operator on /ui"]);
    assert!(!ada.may("tickets.list"));
    assert!(!ada.may_on("tickets.get", "KILN-1"));
    assert!(!ada.holds_anywhere("tickets.list"));
}

#[test]
fn self_is_the_service_being_called() {
    assert_eq!(ScopeRef::parse_checked("self"), Ok(ScopeRef::Everywhere));
    let ada = ada(&["operator on self"]);
    assert!(ada.may("dyn.connect") && ada.may("dyn.peer.shop.items.list") && ada.may("tickets.list"));
    assert!(ada.may_everywhere("dyn.connect"));
}

// --- inside a call it covers, an address reads as `*` -----------------------

#[test]
fn inside_the_call_an_address_reads_as_everywhere() {
    let ada = ada(&["viewer on /tickets"]);
    let reach = ada.reach("tickets.list").unwrap();
    assert!(reach.is_everywhere());
    assert_eq!(reach.held_on(), [ScopeRef::Everywhere]);
    assert!(reach.allows("KILN-1"));
    assert!(ada.may_on("tickets.get", "KILN-1"));
}

#[test]
fn a_reach_on_an_address_ends_when_the_membership_does() {
    let ada = ada(&["operator on /dyn.*"]);
    let reach = ada.reach("dyn.peer.shop.items.list").unwrap();
    ada.loses_everything();
    assert!(reach.current().is_none());
    assert!(!reach.allows("KILN-1"));
}

// --- the whole-service methods (KEEL-31 stays shut) --------------------------

#[test]
fn a_whole_service_method_is_held_on_its_own_address_or_above() {
    for scope in ["*", "self", "/dyn", "/dyn.connect", "/dyn.*"] {
        let ada = ada(&[&format!("operator on {scope}")]);
        assert!(ada.may_everywhere("dyn.connect"), "operator on {scope}");
    }
    for scope in ["/ui", "/ui.*", "/dyn.peer.*", "/dyn.peer.shop.*", "/dyn.disconnect", "/dynamo"] {
        let ada = ada(&[&format!("operator on {scope}")]);
        assert!(!ada.may_everywhere("dyn.connect"), "operator on {scope}");
    }
}

#[test]
fn an_admin_on_a_data_scope_is_still_refused_a_whole_service_method() {
    let ada = ada(&["admin on KILN", "admin on KILN-1"]);
    assert!(ada.may_on("tickets.get", "KILN-1"));
    match ada.refused_everywhere("dyn.connect") {
        Some(Refusal::MissingGrant { scope, held_on, .. }) => {
            assert_eq!(scope, ScopeRef::named("/dyn"), "the refusal names the activation");
            assert_eq!(held_on, [ScopeRef::named("KILN"), ScopeRef::named("KILN-1")]);
        }
        other => panic!("admin on KILN: {other:?}"),
    }
    assert!(ada.gate.check_everywhere(Some(&ada.session), &Grant::new("dyn.connect")).is_err());
}

// --- a ceiling of an address caps as a data ceiling caps ---------------------

#[test]
fn a_session_capped_to_an_address_reaches_only_inside_it() {
    let ada = ada(&["admin on *"]).capped_to(&["admin@/dyn"]);
    assert!(ada.may("dyn.connect"));
    assert!(ada.may_everywhere("dyn.connect"));
    assert!(!ada.may("dyn.peer.shop.items.list"));
    assert!(!ada.may("tickets.list"));
    assert!(!ada.may_on("tickets.get", "KILN-1"));
    assert!(!ada.holds_anywhere("tickets.list"));
}

#[test]
fn a_session_capped_to_a_data_scope_cannot_use_an_address_membership_everywhere() {
    let on_dyn = ada(&["operator on /dyn.*"]).capped_to(&["operator@KILN"]);
    let on_all = ada(&["operator on *"]).capped_to(&["operator@KILN"]);
    assert!(!on_dyn.may_everywhere("dyn.connect"));
    // A read inside the address answers from KILN alone, as `*` capped to KILN does.
    let kiln = [ScopeRef::named("KILN")];
    assert_eq!(on_dyn.reach("dyn.peer.shop.items.list").unwrap().held_on(), kiln);
    assert_eq!(on_all.reach("dyn.peer.shop.items.list").unwrap().held_on(), kiln);
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
    assert!(ada.may_everywhere("dyn.connect"));
    assert!(!ada.may("dyn.disconnect"));
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
    assert!(!ada(&["operator on /dyn"]).may("dynamo.connect"));
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
        assert!(!ada.may_everywhere("dyn.connect"), "{raw:?}");
        assert!(!ada.may_on("tickets.get", "KILN-1"), "{raw:?}");
        assert!(!ada.holds_anywhere("tickets.list"), "{raw:?}");
    }
}

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

// --- the gate owns addresses -------------------------------------------------

#[test]
fn a_resolver_cannot_put_an_address_in_a_chain() {
    let ada = ada_with(&["operator on /ui.*", "operator on /dyn"], Arc::new(Forger));
    assert!(!ada.may_on("tickets.get", "KILN-1"));
    assert!(!ada.may_on("tickets.get", "/dyn"));
    assert!(!ada.gate.check(Some(&ada.session), &Grant::new("tickets.get"), Some("/ui.*")).is_ok());
}

#[test]
fn a_data_scope_beginning_with_a_slash_is_no_data_scope() {
    // Held raw as if a service had named a data scope `/KILN`, and a
    // resolver that answers it: it is an address, and covers no call here.
    struct Slashed;
    impl Resolve for Slashed {
        fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
            Some(vec![ScopeRef::named(target), ScopeRef::named("/KILN"), ScopeRef::Everywhere])
        }
    }
    let ada = ada_with(&[], Arc::new(Slashed)).also_holds_raw("viewer", "/KILN");
    assert!(!ada.may_on("tickets.get", "KILN-1"));
    assert!(!ada.may_on("tickets.get", "/KILN"));
    assert!(!ada.holds_anywhere("tickets.list"));
}

#[test]
fn told_no_address_the_gate_holds_an_address_scope_on_nothing() {
    let ada = ada(&["admin on /dyn.*"]);
    assert!(ada.gate.check(Some(&ada.session), &Grant::new("dyn.connect"), None).is_err());
    assert!(ada.gate.check_everywhere(Some(&ada.session), &Grant::new("dyn.connect")).is_err());
    assert!(ada.gate.reach_of_public(Some(&ada.session), &Grant::new("dyn.connect")).is_empty());
    assert!(!ada.gate.reach_of_public_at(Some(&ada.session), &call("dyn.connect")).is_empty());
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
    assert!(ada.may_everywhere("dyn.connect"));
    assert!(!ada.may_also("auth.grant"));
}

#[test]
fn a_reach_on_an_address_allows_only_its_own_grant() {
    let ada = ada(&["operator on /dyn.*"]);
    let reach = ada.reach("dyn.peer.shop.items.list").unwrap();
    assert_eq!(reach.grant(), Some(&Grant::new("dyn.{peer}")));
    assert!(reach.allows("KILN-1"));
    assert!(!ada.may_also("dyn.{peer}"), "the same grant, asked outside the call, holds nothing");
}

// --- one spelling for the root (review F3) -----------------------------------

#[test]
fn self_stored_raw_holds_nothing_anywhere() {
    for raw in [ScopeRef::parse("self"), serde_json::from_str::<ScopeRef>("\"self\"").unwrap()] {
        assert_eq!(raw, ScopeRef::named("self"), "the lenient spelling is a name");
        let ada = ada(&[]).also_holds_raw("admin", raw.as_str());
        assert!(!ada.may("dyn.connect"));
        assert!(!ada.may_everywhere("dyn.connect"));
        assert!(!ada.may_on("tickets.get", "KILN-1"));
        assert!(!ada.holds_anywhere("tickets.list"));
        assert!(!ada.may_also("auth.grant"));
    }
}

#[test]
fn a_ceiling_of_self_stored_raw_allows_nothing() {
    let ada = ada(&["admin on *"]).capped_to(&["admin@self"]);
    assert!(!ada.may("dyn.connect"));
    assert!(!ada.may_on("tickets.get", "KILN-1"));
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
    assert!(!ada.may_on("tickets.get", "KILN-1"));
}

// --- the dispatcher's contract (review F5, F6) --------------------------------

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
