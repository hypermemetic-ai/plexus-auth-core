//! AUTHZ-CORE-6 (revived by R-0): exhaustive wildcard-match and
//! role-inheritance algorithm tests.
//!
//! `Scope::matches` and `ScopeRegistry::expand_role` sit on the dispatch hot
//! path (R-5 / AUTHZ-CORE-5). A subtle wildcard-match bug or a
//! transitive-inheritance miss is a security regression that bypasses the
//! gate silently. AUTHZ-CORE-4's source-side tests cover a representative
//! set; this file is the exhaustive matrix that pins the algorithm's
//! contract — lifted verbatim from AUTHZ-S01-output §4's truth table via
//! AUTHZ-CORE-6 §"Required behavior".
//!
//! The cycle-rejection cases live with AUTHZ-CORE-4's tests (the unit module
//! in `src/scope_registry.rs`), including the defense-in-depth smoke test
//! that injects a cyclic graph past `build()` by direct internal
//! construction.

use std::collections::BTreeSet;

use plexus_auth_core::audit::RoleName;
use plexus_auth_core::{Scope, ScopeRegistry};

fn scope(s: &str) -> Scope {
    Scope::try_new(s).expect("test scopes are grammatical")
}

fn role(s: &str) -> RoleName {
    RoleName::try_new(s).expect("test role names are grammatical")
}

// ---------------------------------------------------------------------------
// Wildcard-match truth table (one assertion per row).
// ---------------------------------------------------------------------------

/// Held `*` matches every requirement.
#[test]
fn held_star_matches_concrete_two_segments() {
    assert!(scope("*").matches(&scope("cone.send_message")));
}

#[test]
fn held_star_matches_concrete_three_segments() {
    assert!(scope("*").matches(&scope("forms.list.detail")));
}

#[test]
fn held_star_matches_required_star() {
    assert!(scope("*").matches(&scope("*")));
}

/// Exact scopes match themselves and nothing else.
#[test]
fn exact_matches_itself() {
    assert!(scope("cone.send_message").matches(&scope("cone.send_message")));
}

#[test]
fn exact_does_not_match_sibling() {
    assert!(!scope("cone.send_message").matches(&scope("cone.read_thread")));
}

#[test]
fn exact_does_not_match_extension_of_itself() {
    // `cone.send_message` held must not satisfy `cone.send_message_extended`
    // — exactness is full-identifier, not prefix.
    assert!(!scope("cone.send_message").matches(&scope("cone.send_message_extended")));
}

/// Trailing `.*` is a segment-prefix wildcard.
#[test]
fn prefix_wildcard_matches_one_downstream_segment() {
    assert!(scope("cone.*").matches(&scope("cone.send_message")));
}

#[test]
fn prefix_wildcard_matches_multiple_downstream_segments() {
    assert!(scope("cone.*").matches(&scope("cone.threads.list")));
}

#[test]
fn prefix_wildcard_does_not_match_other_namespace() {
    assert!(!scope("cone.*").matches(&scope("forms.list")));
}

/// THE LOAD-BEARING BOUNDARY TEST (AUTHZ-CORE-6 acceptance 4, risk 1).
///
/// Segment-boundary invariant: `cone.*` grants the `cone` subtree, where
/// "subtree" is delimited by the `.` segment separator — NOT by string
/// prefix. `cone_extended.thing` string-starts-with `cone` but its first
/// segment is `cone_extended`, a different namespace. A refactor that
/// implements held-`X.*` as `required.starts_with("X")` (dropping the `.`
/// boundary check) silently grants `cone.*` holders access to every
/// namespace that merely shares the spelling prefix — an authorization
/// bypass. If this test breaks, that refactor happened.
#[test]
fn prefix_wildcard_respects_segment_boundary() {
    assert!(!scope("cone.*").matches(&scope("cone_extended.thing")));
}

#[test]
fn deep_prefix_wildcard_matches_direct_child() {
    assert!(scope("cone.threads.*").matches(&scope("cone.threads.list")));
}

#[test]
fn deep_prefix_wildcard_matches_grandchild() {
    assert!(scope("cone.threads.*").matches(&scope("cone.threads.list.detail")));
}

#[test]
fn deep_prefix_wildcard_does_not_match_uncle() {
    assert!(!scope("cone.threads.*").matches(&scope("cone.send_message")));
}

/// Bare-`*`-required edge case (AUTHZ-CORE-6 risk 2): a required `*` is
/// satisfied ONLY by a held `*`. Holding any concrete scope does not satisfy
/// "all" — matching is not "satisfied if held set non-empty".
#[test]
fn concrete_held_does_not_satisfy_required_star() {
    assert!(!scope("cone.send_message").matches(&scope("*")));
}

#[test]
fn exact_single_namespace_matches_itself() {
    assert!(scope("forms.list").matches(&scope("forms.list")));
}

// ---------------------------------------------------------------------------
// Inheritance / expand_role table.
// ---------------------------------------------------------------------------

fn scopes(items: &[&str]) -> BTreeSet<Scope> {
    items.iter().map(|s| scope(s)).collect()
}

#[test]
fn expand_role_flat_role() {
    let reg = ScopeRegistry::builder()
        .role("viewer", &["forms.list"])
        .build()
        .unwrap();
    assert_eq!(reg.expand_role(&role("viewer")), scopes(&["forms.list"]));
}

#[test]
fn expand_role_single_inheritance_unions() {
    let reg = ScopeRegistry::builder()
        .role("viewer", &["forms.list"])
        .role("editor", &["forms.write"])
        .inherits(&["viewer"])
        .build()
        .unwrap();
    assert_eq!(
        reg.expand_role(&role("editor")),
        scopes(&["forms.write", "forms.list"])
    );
}

#[test]
fn expand_role_transitive_chain_unions() {
    let reg = ScopeRegistry::builder()
        .role("a", &["x.read"])
        .role("b", &["y.read"])
        .inherits(&["a"])
        .role("c", &["z.read"])
        .inherits(&["b"])
        .build()
        .unwrap();
    assert_eq!(
        reg.expand_role(&role("c")),
        scopes(&["x.read", "y.read", "z.read"])
    );
}

// Row 4 of the CORE-6 registry table (`a inherits b`, `b inherits a`) is the
// build-time `InheritanceCycle` rejection — covered by AUTHZ-CORE-4's tests
// in src/scope_registry.rs (build_rejects_two_role_cycle_with_path), per the
// table's own note.

#[test]
fn expand_role_empty_grant_with_transitive_inherits() {
    let reg = ScopeRegistry::builder()
        .role("viewer", &["forms.list"])
        .role("editor", &["forms.write"])
        .inherits(&["viewer"])
        .role("tenant_owner", &[])
        .inherits(&["editor"])
        .build()
        .unwrap();
    assert_eq!(
        reg.expand_role(&role("tenant_owner")),
        scopes(&["forms.write", "forms.list"])
    );
}

// ---------------------------------------------------------------------------
// effective_scopes table.
// ---------------------------------------------------------------------------

/// The registry shared by the `effective_scopes` rows ("registry as above").
fn viewer_editor_registry() -> ScopeRegistry {
    ScopeRegistry::builder()
        .role("viewer", &["forms.list"])
        .role("editor", &["forms.write"])
        .inherits(&["viewer"])
        .build()
        .unwrap()
}

#[test]
fn effective_scopes_single_role() {
    let reg = viewer_editor_registry();
    assert_eq!(
        reg.effective_scopes(&[role("viewer")]),
        scopes(&["forms.list"])
    );
}

#[test]
fn effective_scopes_unions_multiple_roles() {
    let reg = viewer_editor_registry();
    assert_eq!(
        reg.effective_scopes(&[role("viewer"), role("editor")]),
        scopes(&["forms.list", "forms.write"])
    );
}

#[test]
fn effective_scopes_empty_roles_is_empty() {
    let reg = viewer_editor_registry();
    assert_eq!(reg.effective_scopes(&[]), BTreeSet::new());
}

/// Wildcard grants survive expansion verbatim: the held `*` is preserved as
/// a held scope; the matching at use-site does the wildcard math.
///
/// NOTE on posture: `admin = {*}` is implemented per AUTHZ-CORE-6 but is a
/// DEV posture — whether wildcard role grants are permitted in production is
/// an open human question (R-S01 open question 5).
#[test]
fn effective_scopes_preserves_wildcard_grant() {
    let reg = ScopeRegistry::builder()
        .role("admin", &["*"])
        .build()
        .unwrap();
    assert_eq!(reg.effective_scopes(&[role("admin")]), scopes(&["*"]));
}

// ---------------------------------------------------------------------------
// End-to-end gate shape: effective_scopes + matches composed, the way the
// R-5 dispatch gate will consume this module.
// ---------------------------------------------------------------------------

#[test]
fn gate_composition_roles_to_decision() {
    let reg = ScopeRegistry::builder()
        .role("viewer", &["forms.list"])
        .role("editor", &["forms.*"])
        .inherits(&["viewer"])
        .build()
        .unwrap();

    let satisfies = |held_roles: &[RoleName], required: &Scope| {
        reg.effective_scopes(held_roles)
            .iter()
            .any(|held| held.matches(required))
    };

    // viewer can list, cannot write.
    assert!(satisfies(&[role("viewer")], &scope("forms.list")));
    assert!(!satisfies(&[role("viewer")], &scope("forms.write")));
    // editor inherits viewer and holds the forms.* wildcard.
    assert!(satisfies(&[role("editor")], &scope("forms.list")));
    assert!(satisfies(&[role("editor")], &scope("forms.write")));
    // the wildcard is segment-bounded even composed through roles.
    assert!(!satisfies(&[role("editor")], &scope("forms_extended.thing")));
    // no roles, no access.
    assert!(!satisfies(&[], &scope("forms.list")));
}
