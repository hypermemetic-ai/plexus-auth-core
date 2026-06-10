//! Role + `ScopeRegistry` + inheritance — the hub-level roles→scopes source
//! of truth (R-0; revives AUTHZ-CORE-4 + AUTHZ-CORE-6 verbatim).
//!
//! Default-deny dispatch (AUTHZ-CORE-1/5, wired in R-5) and schema projection
//! (AUTHZ-PRIVACY-3) need a single source of truth that maps roles to scopes,
//! identifies which methods are public, and resolves a method's required
//! scope set. Per AUTHZ-S01-output §4: "When a hub routes to a child
//! activation, the child's required scopes are reported by the macro. The
//! hub-level `ScopeRegistry` is the **single source of truth** for which
//! roles map to which scopes." This separation lets a backend assemble
//! scope-aware activations from third-party crates without those crates
//! knowing the deployment's role taxonomy.
//!
//! # The role model (R-S01 §b, user-ratified)
//!
//! - **Scopes are atomic** capability identifiers (`facet.write`-style):
//!   dotted lowercase segments, segment-bounded trailing `.*` wildcard, bare
//!   `*` for "all scopes".
//! - **Roles are named scope-sets** with transitive inheritance,
//!   cycle-rejected at [`ScopeRegistryBuilder::build`] time.
//! - **Tokens carry roles** (the `roles` claim, minted by plexus-idp today);
//!   each backend's hub builds a `ScopeRegistry` mapping its deployment's
//!   role taxonomy to its scopes; the gate computes
//!   [`ScopeRegistry::effective_scopes`]`(AuthContext.roles)` and checks
//!   [`Scope::matches`]`(required)`.
//!
//! # Deferred / out of scope here
//!
//! - **Negative scopes** ("admin minus delete_message") are NOT implemented
//!   in v1 per AUTHZ-S01-output §4's Tier B resolution. A deployment wanting
//!   subtractive grants must model them as multiple roles. A future ticket
//!   can add the form if a real use case surfaces.
//! - **Gate/dispatch wiring** (`DynamicHub::with_scope_registry`, the
//!   default-deny consult) is R-5 territory (revives AUTHZ-CORE-1 + CORE-5);
//!   this module is pure types + algorithm.
//!
//! # Deployment responsibility
//!
//! A crate exposing a scope-decorated activation declares its required
//! scopes on its methods; the deploying hub's `ScopeRegistry` decides who
//! has those scopes. If the deploying hub forgets to include a role granting
//! the third-party scopes, those methods are unreachable under default-deny.
//! Auditing the registry against the composed activation set is a
//! deployment responsibility (see AUTHZ-FLOWS-3).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::audit::RoleName;
use crate::capabilities::{is_valid_path_segment, MethodPath};
use crate::credential::Scope;

// ---------------------------------------------------------------------------
// Scope grammar + matching (AUTHZ-CORE-4; truth table pinned by AUTHZ-CORE-6)
// ---------------------------------------------------------------------------

/// Why a [`Scope::try_new`] rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// The input was empty.
    Empty,
    /// The input did not match the scope grammar (carries the offending
    /// input).
    InvalidFormat(String),
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeError::Empty => write!(f, "scope must not be empty"),
            ScopeError::InvalidFormat(s) => write!(
                f,
                "invalid scope {s:?}: expected bare `*`, dot-separated lowercase \
                 identifiers ([a-z][a-z0-9_]*), or such a path with a trailing `.*` \
                 segment wildcard"
            ),
        }
    }
}

impl std::error::Error for ScopeError {}

/// Is `s` a valid scope per the AUTHZ-S01-output §1/§4 grammar?
///
/// Grammar: bare `*`, OR dot-separated segments each matching
/// `[a-z][a-z0-9_]*`, OR such a path with one trailing `.*` wildcard
/// segment. Wildcards anywhere else are rejected.
fn is_valid_scope(s: &str) -> bool {
    if s == "*" {
        return true;
    }
    // Optional trailing `.*` — the body before it must be a non-empty valid
    // dotted path. `.*` alone has an empty body and is rejected.
    let body = s.strip_suffix(".*").unwrap_or(s);
    if body.is_empty() {
        return false;
    }
    body.split('.').all(is_valid_path_segment)
}

impl Scope {
    /// Construct a `Scope`, validating the canonical grammar.
    ///
    /// Accepts: bare `*`, dot-separated lowercase identifiers (each segment
    /// `[a-z][a-z0-9_]*`), and an optional trailing `.*` segment wildcard.
    /// Rejects everything else with a [`ScopeError`] carrying the offending
    /// input.
    ///
    /// Per AUTHZ-CORE-4. The pre-existing unvalidated [`Scope::new`]
    /// constructor remains for wire-decoded values; registry construction
    /// goes through this validating path.
    pub fn try_new(s: impl Into<String>) -> Result<Self, ScopeError> {
        let s = s.into();
        if s.is_empty() {
            return Err(ScopeError::Empty);
        }
        if !is_valid_scope(&s) {
            return Err(ScopeError::InvalidFormat(s));
        }
        Ok(Self::new(s))
    }

    /// True for the bare `*` and for any `<prefix>.*` form.
    pub fn is_wildcard(&self) -> bool {
        self.as_str() == "*" || self.as_str().ends_with(".*")
    }

    /// Does the holder of `self` satisfy the requirement `required`?
    ///
    /// Returns true iff:
    /// - `self` is the bare `*` (matches everything), OR
    /// - `self == required` (exact match), OR
    /// - `self` ends with `.*` AND its prefix-without-`.*` is a
    ///   **segment-prefix** of `required`.
    ///
    /// Segment-prefix matching is the subtle case: `cone.*` matches
    /// `cone.send_message` AND `cone.threads.list` (multiple downstream
    /// segments) but does NOT match `cone_extended.thing` — the `.` boundary
    /// is mandatory. A plain string-prefix check would silently match
    /// `cone_extended.thing`; that is the exemplar trap AUTHZ-CORE-6's
    /// boundary test pins against.
    ///
    /// The required side never carries wildcards in practice (a method's
    /// required scope is concrete); the holder side may. A required `*` is
    /// only satisfied by a held `*` (via the bare-`*` arm).
    pub fn matches(&self, required: &Scope) -> bool {
        let held = self.as_str();
        if held == "*" {
            return true;
        }
        if self == required {
            return true;
        }
        if let Some(prefix) = held.strip_suffix(".*") {
            let req = required.as_str();
            // Segment-bounded: the required scope must continue with a `.`
            // exactly at the prefix boundary.
            return req.len() > prefix.len()
                && req.starts_with(prefix)
                && req.as_bytes()[prefix.len()] == b'.';
        }
        false
    }
}

// ---------------------------------------------------------------------------
// RoleName grammar (AUTHZ-CORE-4)
// ---------------------------------------------------------------------------

/// Why a [`RoleName::try_new`] rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleNameError {
    /// The input was empty.
    Empty,
    /// The input did not match `[a-z][a-z0-9_]*` (carries the offending
    /// input).
    InvalidFormat(String),
}

impl fmt::Display for RoleNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoleNameError::Empty => write!(f, "role name must not be empty"),
            RoleNameError::InvalidFormat(s) => {
                write!(f, "invalid role name {s:?}: expected [a-z][a-z0-9_]*")
            }
        }
    }
}

impl std::error::Error for RoleNameError {}

impl RoleName {
    /// Construct a `RoleName`, validating the `[a-z][a-z0-9_]*` grammar.
    ///
    /// Per AUTHZ-CORE-4. The pre-existing unvalidated [`RoleName::new`]
    /// constructor remains for wire-decoded values (token claims); registry
    /// construction goes through this validating path.
    pub fn try_new(s: impl Into<String>) -> Result<Self, RoleNameError> {
        let s = s.into();
        if s.is_empty() {
            return Err(RoleNameError::Empty);
        }
        if !is_valid_path_segment(&s) {
            return Err(RoleNameError::InvalidFormat(s));
        }
        Ok(Self::new(s))
    }
}

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

/// A named scope-set with transitive inheritance.
///
/// A `Role` carries a name, a list of granted scopes, an `inherits` list of
/// upstream roles whose scopes are unioned transitively at
/// [`ScopeRegistry::expand_role`] time, and a free-text description.
///
/// Construction performs no validation beyond the field types themselves
/// (per AUTHZ-CORE-4 "no validation beyond field-level"); referential
/// integrity of `inherits` and cycle-freedom are enforced when the role is
/// installed into a registry via [`ScopeRegistryBuilder::build`].
///
/// `Role` is intentionally NOT sealed — the registry's *contents* are
/// deployment-controlled; only the *types* are framework-owned (AUTHZ-0
/// §"Crate-level isolation amplifies the seal").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    name: RoleName,
    scopes: Vec<Scope>,
    inherits: Vec<RoleName>,
    description: String,
}

impl Role {
    /// Construct a `Role` from already-typed fields.
    pub fn new(
        name: RoleName,
        scopes: Vec<Scope>,
        inherits: Vec<RoleName>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name,
            scopes,
            inherits,
            description: description.into(),
        }
    }

    /// The role's name.
    pub fn name(&self) -> &RoleName {
        &self.name
    }

    /// The scopes granted directly by this role (excluding inherited).
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// The upstream roles whose scopes this role unions transitively.
    pub fn inherits(&self) -> &[RoleName] {
        &self.inherits
    }

    /// Free-text description of the role.
    pub fn description(&self) -> &str {
        &self.description
    }
}

// ---------------------------------------------------------------------------
// ScopeRegistryError
// ---------------------------------------------------------------------------

/// Why [`ScopeRegistryBuilder::build`] rejected the declared taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRegistryError {
    /// A role name (declared or referenced in `inherits`) failed the
    /// `[a-z][a-z0-9_]*` grammar.
    InvalidRoleName(RoleNameError),
    /// A granted scope failed the scope grammar.
    InvalidScope(ScopeError),
    /// The same role name was declared twice. Silent override in an auth
    /// taxonomy is a footgun; redeclaration is rejected explicitly.
    DuplicateRole(RoleName),
    /// A role's `inherits` references a role that was never declared.
    UnknownInheritedRole {
        /// The role whose `inherits` list is dangling.
        role: RoleName,
        /// The undeclared role it references.
        inherits: RoleName,
    },
    /// The inheritance graph contains a cycle. Carries the cycle path
    /// (first element repeated at the end, e.g. `[a, b, a]`).
    InheritanceCycle {
        /// The roles forming the cycle, in walk order, closing on the first.
        path: Vec<RoleName>,
    },
    /// [`ScopeRegistryBuilder::inherits`] (or `description`) was called
    /// before any [`ScopeRegistryBuilder::role`] — there is no
    /// most-recently-added role to modify.
    InheritsBeforeRole,
}

impl fmt::Display for ScopeRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeRegistryError::InvalidRoleName(e) => write!(f, "{e}"),
            ScopeRegistryError::InvalidScope(e) => write!(f, "{e}"),
            ScopeRegistryError::DuplicateRole(r) => {
                write!(f, "role {r} declared more than once")
            }
            ScopeRegistryError::UnknownInheritedRole { role, inherits } => write!(
                f,
                "role {role} inherits undeclared role {inherits}"
            ),
            ScopeRegistryError::InheritanceCycle { path } => {
                let rendered: Vec<&str> = path.iter().map(|r| r.as_str()).collect();
                write!(f, "role inheritance cycle: {}", rendered.join(" -> "))
            }
            ScopeRegistryError::InheritsBeforeRole => write!(
                f,
                "inherits()/description() called before any role() — nothing to modify"
            ),
        }
    }
}

impl std::error::Error for ScopeRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScopeRegistryError::InvalidRoleName(e) => Some(e),
            ScopeRegistryError::InvalidScope(e) => Some(e),
            _ => None,
        }
    }
}

impl From<RoleNameError> for ScopeRegistryError {
    fn from(e: RoleNameError) -> Self {
        ScopeRegistryError::InvalidRoleName(e)
    }
}

impl From<ScopeError> for ScopeRegistryError {
    fn from(e: ScopeError) -> Self {
        ScopeRegistryError::InvalidScope(e)
    }
}

// ---------------------------------------------------------------------------
// ScopeRegistry
// ---------------------------------------------------------------------------

/// Hub-level roles→scopes source of truth. Built once at hub construction
/// via [`ScopeRegistry::builder`], immutable thereafter.
///
/// Holds the role table, the set of public methods, and a per-method
/// explicit-scope overlay (used when the macro emits explicit `scope = ...`
/// literals; otherwise [`ScopeRegistry::required_scopes_for`] resolves the
/// implicit `<activation>.<method>` requirement at lookup time).
///
/// The lookups dispatch (AUTHZ-CORE-1/5, R-5) and schema projection
/// (AUTHZ-PRIVACY-3) consume:
/// - "what scopes are required for this method?" —
///   [`ScopeRegistry::required_scopes_for`]
/// - "is this method public?" — [`ScopeRegistry::is_public`]
/// - "expand this role to its transitive scope set" —
///   [`ScopeRegistry::expand_role`] / [`ScopeRegistry::effective_scopes`]
///
/// `Default` is the empty registry: no roles, no public methods, no
/// overlays. A hub without a registry is treated as this empty registry —
/// with default-deny OFF that is the harmless no-op; with default-deny ON
/// every gated method denies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeRegistry {
    roles: BTreeMap<RoleName, Role>,
    public_methods: BTreeSet<MethodPath>,
    method_overlays: BTreeMap<MethodPath, Vec<Scope>>,
}

impl ScopeRegistry {
    /// Start declaring a deployment's role taxonomy.
    pub fn builder() -> ScopeRegistryBuilder {
        ScopeRegistryBuilder::default()
    }

    /// Look up a declared role by name.
    pub fn role(&self, name: &RoleName) -> Option<&Role> {
        self.roles.get(name)
    }

    /// True iff the method was declared public via
    /// [`ScopeRegistryBuilder::public_method`].
    pub fn is_public(&self, method: &MethodPath) -> bool {
        self.public_methods.contains(method)
    }

    /// The scopes required to invoke `method`.
    ///
    /// Returns the explicit overlay if [`ScopeRegistryBuilder::method_scopes`]
    /// declared one; otherwise the implicit requirement derived from the
    /// method path itself.
    ///
    /// Implicit-scope note: AUTHZ-CORE-4 phrases the implicit rule as
    /// `<activation>.<method>`; for the canonical two-segment paths the full
    /// dotted path IS `<activation>.<method>`. For deeper paths
    /// (e.g. `solar.earth.luna.info`) this implementation uses the **full
    /// dotted path** as the implicit scope rather than
    /// first-segment + last-segment, because collapsing the middle segments
    /// would alias distinct methods (`solar.earth.luna.info` and
    /// `solar.mars.info` would both require `solar.info` — granting one
    /// would grant the other, an authorization hazard). Wildcard role grants
    /// (`solar.*`) still cover the whole subtree.
    pub fn required_scopes_for(&self, method: &MethodPath) -> Vec<Scope> {
        if let Some(explicit) = self.method_overlays.get(method) {
            return explicit.clone();
        }
        vec![Scope::new(method.as_str())]
    }

    /// The transitive union of scopes granted by `role`: its own scopes,
    /// plus its `inherits` roles' scopes, plus theirs, deduplicated.
    ///
    /// A role unknown to this registry expands to the empty set — token
    /// claims are external input, and a role the deployment never declared
    /// grants nothing (default-deny posture).
    ///
    /// Defense in depth: the walk carries a visited set, so it terminates
    /// even on a cyclic role graph. Cycles cannot arise through
    /// [`ScopeRegistryBuilder::build`] (which rejects them); the visited set
    /// is the layered second defense AUTHZ-CORE-6 risk 3 calls for.
    pub fn expand_role(&self, role: &RoleName) -> BTreeSet<Scope> {
        let mut out = BTreeSet::new();
        let mut visited: HashSet<&RoleName> = HashSet::new();
        let mut frontier: Vec<&RoleName> = vec![role];
        while let Some(name) = frontier.pop() {
            if !visited.insert(name) {
                continue;
            }
            if let Some(def) = self.roles.get(name) {
                out.extend(def.scopes.iter().cloned());
                frontier.extend(def.inherits.iter());
            }
        }
        out
    }

    /// The union of [`ScopeRegistry::expand_role`] over each held role —
    /// the holder's full effective scope set.
    ///
    /// Wildcard scopes (`*`, `<prefix>.*`) are preserved as held scopes in
    /// the result; the wildcard math happens at the use-site via
    /// [`Scope::matches`].
    pub fn effective_scopes(&self, roles: &[RoleName]) -> BTreeSet<Scope> {
        roles.iter().flat_map(|r| self.expand_role(r)).collect()
    }
}

// ---------------------------------------------------------------------------
// ScopeRegistryBuilder
// ---------------------------------------------------------------------------

/// One declared-but-not-yet-validated role inside the builder.
#[derive(Debug, Clone)]
struct RoleDraft {
    name: String,
    scopes: Vec<String>,
    inherits: Vec<String>,
    description: String,
}

/// Chainable declaration of a deployment's role taxonomy
/// (AUTHZ-S01-output §4's registration syntax).
///
/// Role names, scope strings, and inherits references are accepted as bare
/// strings for chaining ergonomics and validated together at
/// [`ScopeRegistryBuilder::build`] time — grammar violations, duplicate
/// roles, dangling `inherits`, and inheritance cycles all surface as
/// [`ScopeRegistryError`]s from `build()`, never as panics.
///
/// # Example
///
/// ```
/// use plexus_auth_core::scope_registry::ScopeRegistry;
/// use plexus_auth_core::MethodPath;
///
/// let registry = ScopeRegistry::builder()
///     .role("viewer", &["forms.list"])
///     .role("editor", &["forms.write"])
///     .inherits(&["viewer"])
///     .role("tenant_owner", &[])
///     .inherits(&["editor"])
///     .role("admin", &["*"])
///     .public_method(MethodPath::try_new("auth.login").unwrap())
///     .build()
///     .unwrap();
/// assert!(registry.is_public(&MethodPath::try_new("auth.login").unwrap()));
/// ```
///
/// # Wildcard grants are a development posture
///
/// `admin = {*}` (the bare-`*` grant) is implemented per AUTHZ-CORE-6 and is
/// useful in development. **Whether wildcard role grants are permitted in
/// production deployments is an open human question (R-S01 open question
/// 5); treat `*` grants as dev-posture until that call is made.** Production
/// taxonomies should prefer enumerated scopes or segment-bounded prefix
/// wildcards (`facet.*`) per activation.
#[derive(Debug, Clone, Default)]
pub struct ScopeRegistryBuilder {
    roles: Vec<RoleDraft>,
    public_methods: BTreeSet<MethodPath>,
    method_overlays: BTreeMap<MethodPath, Vec<Scope>>,
    modifier_before_role: bool,
}

impl ScopeRegistryBuilder {
    /// Declare a role granting the listed scopes. Returns the builder for
    /// chaining; subsequent [`ScopeRegistryBuilder::inherits`] /
    /// [`ScopeRegistryBuilder::description`] calls modify this role until
    /// the next `role()` call.
    pub fn role(mut self, name: impl Into<String>, scopes: &[&str]) -> Self {
        self.roles.push(RoleDraft {
            name: name.into(),
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            inherits: Vec::new(),
            description: String::new(),
        });
        self
    }

    /// Declare that the most-recently-added role inherits the listed roles'
    /// scopes transitively. Calling this before any `role()` is recorded
    /// and surfaces as [`ScopeRegistryError::InheritsBeforeRole`] at
    /// `build()` time.
    pub fn inherits(mut self, parents: &[&str]) -> Self {
        match self.roles.last_mut() {
            Some(draft) => draft
                .inherits
                .extend(parents.iter().map(|s| (*s).to_string())),
            None => self.modifier_before_role = true,
        }
        self
    }

    /// Attach a free-text description to the most-recently-added role.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        match self.roles.last_mut() {
            Some(draft) => draft.description = description.into(),
            None => self.modifier_before_role = true,
        }
        self
    }

    /// Declare a method publicly callable (no scope required).
    pub fn public_method(mut self, method: MethodPath) -> Self {
        self.public_methods.insert(method);
        self
    }

    /// Overlay explicit required scopes for a method (used when the macro
    /// emitted explicit `scope = ...` literals; otherwise the implicit
    /// `<activation>.<method>` rule applies at lookup time).
    pub fn method_scopes(mut self, method: MethodPath, scopes: &[Scope]) -> Self {
        self.method_overlays.insert(method, scopes.to_vec());
        self
    }

    /// Validate the declared taxonomy and freeze it into a
    /// [`ScopeRegistry`].
    ///
    /// Errors (in check order): modifier-before-role, role-name grammar,
    /// scope grammar, duplicate role, dangling `inherits` reference,
    /// inheritance cycle. Cycle detection is iterative (explicit stack) —
    /// no recursion, no stack overflow, no hang, regardless of taxonomy
    /// size (AUTHZ-CORE-4 acceptance 7).
    pub fn build(self) -> Result<ScopeRegistry, ScopeRegistryError> {
        if self.modifier_before_role {
            return Err(ScopeRegistryError::InheritsBeforeRole);
        }

        // Grammar validation + duplicate detection.
        let mut roles: BTreeMap<RoleName, Role> = BTreeMap::new();
        for draft in self.roles {
            let name = RoleName::try_new(draft.name)?;
            let scopes = draft
                .scopes
                .into_iter()
                .map(Scope::try_new)
                .collect::<Result<Vec<_>, _>>()?;
            let inherits = draft
                .inherits
                .into_iter()
                .map(RoleName::try_new)
                .collect::<Result<Vec<_>, _>>()?;
            if roles.contains_key(&name) {
                return Err(ScopeRegistryError::DuplicateRole(name));
            }
            roles.insert(
                name.clone(),
                Role::new(name, scopes, inherits, draft.description),
            );
        }

        // Referential integrity: every inherits target must be declared.
        for role in roles.values() {
            for parent in role.inherits() {
                if !roles.contains_key(parent) {
                    return Err(ScopeRegistryError::UnknownInheritedRole {
                        role: role.name().clone(),
                        inherits: parent.clone(),
                    });
                }
            }
        }

        // Cycle rejection (AUTHZ-CORE-4 acceptance 7).
        if let Some(path) = detect_inheritance_cycle(&roles) {
            return Err(ScopeRegistryError::InheritanceCycle { path });
        }

        Ok(ScopeRegistry {
            roles,
            public_methods: self.public_methods,
            method_overlays: self.method_overlays,
        })
    }
}

/// Find a cycle in the role-inheritance graph, if any, returning its path
/// (closing on the first repeated role, e.g. `[a, b, a]`).
///
/// Iterative three-color DFS with an explicit stack: bounded memory, no
/// recursion, terminates on every finite graph. Precondition: every
/// `inherits` target exists in `roles` (build checks referential integrity
/// first).
fn detect_inheritance_cycle(roles: &BTreeMap<RoleName, Role>) -> Option<Vec<RoleName>> {
    #[derive(Clone, Copy, PartialEq)]
    enum Color {
        /// On the current DFS path.
        Gray,
        /// Fully explored; cannot be part of an undiscovered cycle.
        Black,
    }

    let mut color: HashMap<&RoleName, Color> = HashMap::new();

    for start in roles.keys() {
        if color.contains_key(start) {
            continue;
        }
        // Stack of (role, index of next inherits-edge to explore).
        let mut stack: Vec<(&RoleName, usize)> = vec![(start, 0)];
        color.insert(start, Color::Gray);

        while let Some(&(node, edge_idx)) = stack.last() {
            let inherits = roles
                .get(node)
                .expect("referential integrity checked before cycle detection")
                .inherits();
            if edge_idx < inherits.len() {
                stack.last_mut().expect("stack non-empty inside loop").1 += 1;
                let child = &inherits[edge_idx];
                match color.get(child) {
                    Some(Color::Gray) => {
                        // Cycle: slice the current path from the first
                        // occurrence of `child`, then close on it.
                        let pos = stack
                            .iter()
                            .position(|(n, _)| *n == child)
                            .expect("gray node is on the current path");
                        let mut path: Vec<RoleName> =
                            stack[pos..].iter().map(|(n, _)| (*n).clone()).collect();
                        path.push(child.clone());
                        return Some(path);
                    }
                    Some(Color::Black) => {}
                    None => {
                        color.insert(child, Color::Gray);
                        stack.push((child, 0));
                    }
                }
            } else {
                color.insert(node, Color::Black);
                stack.pop();
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests (AUTHZ-CORE-4's unit matrix; AUTHZ-CORE-6's exhaustive truth table
// lives in tests/scope_registry.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(s: &str) -> Scope {
        Scope::try_new(s).unwrap()
    }

    fn role_name(s: &str) -> RoleName {
        RoleName::try_new(s).unwrap()
    }

    fn method(s: &str) -> MethodPath {
        MethodPath::try_new(s).unwrap()
    }

    // -- Scope grammar: exhaustive accept/reject matrix (CORE-4 acceptance 2)

    #[test]
    fn scope_grammar_accepts_canonical_forms() {
        for ok in [
            "*",
            "forms",
            "forms.list",
            "forms.list.detail",
            "forms.*",
            "forms.list.*",
            "cone.send_message",
            "a1.b_2",
            "a_x.y9.*",
            "x",
        ] {
            assert!(
                Scope::try_new(ok).is_ok(),
                "grammar must accept {ok:?}"
            );
        }
    }

    #[test]
    fn scope_grammar_rejects_violations() {
        assert_eq!(Scope::try_new(""), Err(ScopeError::Empty));
        for bad in [
            ".",
            ".*",
            "*.*",
            "**",
            "*a",
            "a*",
            "a.b*",
            "a.*x",
            "a.*.b",
            "*.thing",
            "a.",
            ".a",
            "a..b",
            "a.b.",
            "A.b",
            "a.B",
            "Forms.List",
            "9a.b",
            "_a.b",
            "a-b.c",
            "a b",
            "a.b ",
            " a.b",
            "café.list",
        ] {
            assert_eq!(
                Scope::try_new(bad),
                Err(ScopeError::InvalidFormat(bad.to_string())),
                "grammar must reject {bad:?}"
            );
        }
    }

    #[test]
    fn scope_is_wildcard() {
        assert!(scope("*").is_wildcard());
        assert!(scope("cone.*").is_wildcard());
        assert!(scope("cone.threads.*").is_wildcard());
        assert!(!scope("cone.send_message").is_wildcard());
        assert!(!scope("forms").is_wildcard());
    }

    // -- Scope matching: the canonical six (CORE-4 acceptance 3; the full
    //    CORE-6 matrix lives in tests/scope_registry.rs)

    #[test]
    fn scope_matches_canonical_six() {
        assert!(scope("*").matches(&scope("cone.send_message")));
        assert!(scope("cone.*").matches(&scope("cone.send_message")));
        assert!(scope("cone.*").matches(&scope("cone.threads.list")));
        assert!(!scope("cone.*").matches(&scope("forms.list")));
        assert!(scope("cone.send_message").matches(&scope("cone.send_message")));
        assert!(!scope("cone.send_message").matches(&scope("cone.read_thread")));
    }

    // -- RoleName grammar (CORE-4 acceptance 4)

    #[test]
    fn role_name_grammar_accepts() {
        for ok in ["admin", "a", "tenant_owner", "r2d2", "x_9"] {
            assert!(
                RoleName::try_new(ok).is_ok(),
                "grammar must accept {ok:?}"
            );
        }
    }

    #[test]
    fn role_name_grammar_rejects() {
        assert_eq!(RoleName::try_new(""), Err(RoleNameError::Empty));
        for bad in ["Admin", "9x", "_x", "a.b", "a-b", "a b", "*", "ADMIN", "café"] {
            assert_eq!(
                RoleName::try_new(bad),
                Err(RoleNameError::InvalidFormat(bad.to_string())),
                "grammar must reject {bad:?}"
            );
        }
    }

    // -- Role construction (CORE-4: no validation beyond field-level)

    #[test]
    fn role_construction_carries_fields() {
        let r = Role::new(
            role_name("editor"),
            vec![scope("forms.write")],
            vec![role_name("viewer")],
            "can edit forms",
        );
        assert_eq!(r.name(), &role_name("editor"));
        assert_eq!(r.scopes(), &[scope("forms.write")]);
        assert_eq!(r.inherits(), &[role_name("viewer")]);
        assert_eq!(r.description(), "can edit forms");
    }

    // -- Builder: the §4 example taxonomy (CORE-4 acceptance 5 + 6)

    fn example_registry() -> ScopeRegistry {
        ScopeRegistry::builder()
            .role("viewer", &["forms.list"])
            .description("read-only access")
            .role("editor", &["forms.write"])
            .inherits(&["viewer"])
            .role("tenant_owner", &[])
            .inherits(&["editor"])
            .role("admin", &["*"])
            .public_method(method("auth.login"))
            .method_scopes(method("forms.export"), &[scope("forms.list")])
            .build()
            .expect("the §4 example taxonomy must build")
    }

    #[test]
    fn builder_example_taxonomy_expands_as_pinned() {
        let reg = example_registry();
        assert_eq!(
            reg.expand_role(&role_name("viewer")),
            BTreeSet::from([scope("forms.list")])
        );
        assert_eq!(
            reg.expand_role(&role_name("editor")),
            BTreeSet::from([scope("forms.write"), scope("forms.list")])
        );
        assert_eq!(
            reg.expand_role(&role_name("tenant_owner")),
            BTreeSet::from([scope("forms.write"), scope("forms.list")])
        );
        assert_eq!(
            reg.expand_role(&role_name("admin")),
            BTreeSet::from([scope("*")])
        );
    }

    #[test]
    fn builder_role_lookup_carries_description() {
        let reg = example_registry();
        let viewer = reg.role(&role_name("viewer")).expect("viewer declared");
        assert_eq!(viewer.description(), "read-only access");
    }

    // -- is_public (CORE-4 acceptance 10)

    #[test]
    fn is_public_true_only_for_declared_methods() {
        let reg = example_registry();
        assert!(reg.is_public(&method("auth.login")));
        assert!(!reg.is_public(&method("forms.export")));
        assert!(!reg.is_public(&method("cone.send_message")));
    }

    // -- required_scopes_for (CORE-4 acceptance 9)

    #[test]
    fn required_scopes_explicit_overlay_wins() {
        let reg = example_registry();
        assert_eq!(
            reg.required_scopes_for(&method("forms.export")),
            vec![scope("forms.list")]
        );
    }

    #[test]
    fn required_scopes_implicit_is_the_method_path() {
        let reg = example_registry();
        assert_eq!(
            reg.required_scopes_for(&method("cone.send_message")),
            vec![Scope::new("cone.send_message")]
        );
    }

    // -- Cycle rejection (CORE-4 acceptance 7)

    #[test]
    fn build_rejects_two_role_cycle_with_path() {
        let err = ScopeRegistry::builder()
            .role("a", &["x.one"])
            .inherits(&["b"])
            .role("b", &["y.one"])
            .inherits(&["a"])
            .build()
            .expect_err("cycle must be rejected at build()");
        match err {
            ScopeRegistryError::InheritanceCycle { path } => {
                // Path closes on its first element and contains both roles.
                assert_eq!(path.first(), path.last());
                assert!(path.contains(&role_name("a")));
                assert!(path.contains(&role_name("b")));
                assert_eq!(path.len(), 3, "a->b->a (closed) has length 3");
            }
            other => panic!("expected InheritanceCycle, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_self_cycle() {
        let err = ScopeRegistry::builder()
            .role("a", &["x.one"])
            .inherits(&["a"])
            .build()
            .expect_err("self-cycle must be rejected at build()");
        assert!(matches!(
            err,
            ScopeRegistryError::InheritanceCycle { ref path } if path == &vec![role_name("a"), role_name("a")]
        ));
    }

    #[test]
    fn build_rejects_deep_cycle_without_overflow() {
        // A long chain ending in a cycle: r0 -> r1 -> ... -> r9999 -> r0.
        // Iterative DFS must neither overflow nor hang.
        let n = 10_000;
        let names: Vec<String> = (0..n).map(|i| format!("r{i}")).collect();
        let mut b = ScopeRegistry::builder();
        for i in 0..n {
            let parent = names[(i + 1) % n].clone();
            b = b.role(names[i].as_str(), &[]).inherits(&[parent.as_str()]);
        }
        let err = b.build().expect_err("the loop must be rejected");
        assert!(matches!(err, ScopeRegistryError::InheritanceCycle { .. }));
    }

    #[test]
    fn build_accepts_diamond_inheritance() {
        // a -> b, a -> c, b -> d, c -> d: shared ancestor, no cycle.
        let reg = ScopeRegistry::builder()
            .role("d", &["base.read"])
            .role("b", &["b.write"])
            .inherits(&["d"])
            .role("c", &["c.write"])
            .inherits(&["d"])
            .role("a", &[])
            .inherits(&["b", "c"])
            .build()
            .expect("diamond is acyclic");
        assert_eq!(
            reg.expand_role(&role_name("a")),
            BTreeSet::from([scope("base.read"), scope("b.write"), scope("c.write")])
        );
    }

    // -- Builder error surfaces

    #[test]
    fn build_rejects_unknown_inherited_role() {
        let err = ScopeRegistry::builder()
            .role("a", &["x.one"])
            .inherits(&["ghost"])
            .build()
            .expect_err("dangling inherits must be rejected");
        assert_eq!(
            err,
            ScopeRegistryError::UnknownInheritedRole {
                role: role_name("a"),
                inherits: role_name("ghost"),
            }
        );
    }

    #[test]
    fn build_rejects_duplicate_role() {
        let err = ScopeRegistry::builder()
            .role("a", &["x.one"])
            .role("a", &["y.one"])
            .build()
            .expect_err("redeclaration must be rejected");
        assert_eq!(err, ScopeRegistryError::DuplicateRole(role_name("a")));
    }

    #[test]
    fn build_rejects_invalid_role_name() {
        let err = ScopeRegistry::builder()
            .role("Admin", &["x.one"])
            .build()
            .expect_err("bad role name must be rejected");
        assert!(matches!(err, ScopeRegistryError::InvalidRoleName(_)));
    }

    #[test]
    fn build_rejects_invalid_scope() {
        let err = ScopeRegistry::builder()
            .role("a", &["Bad.Scope"])
            .build()
            .expect_err("bad scope must be rejected");
        assert!(matches!(err, ScopeRegistryError::InvalidScope(_)));
    }

    #[test]
    fn build_rejects_inherits_before_role() {
        let err = ScopeRegistry::builder()
            .inherits(&["a"])
            .role("a", &["x.one"])
            .build()
            .expect_err("inherits() before role() must be rejected");
        assert_eq!(err, ScopeRegistryError::InheritsBeforeRole);
    }

    // -- Empty/default registry (CORE-4 "hub without registry" row)

    #[test]
    fn default_registry_is_empty() {
        let reg = ScopeRegistry::default();
        assert!(!reg.is_public(&method("auth.login")));
        assert!(reg.effective_scopes(&[role_name("admin")]).is_empty());
        assert_eq!(
            reg.required_scopes_for(&method("cone.send_message")),
            vec![Scope::new("cone.send_message")]
        );
        assert_eq!(reg, ScopeRegistry::builder().build().unwrap());
    }

    // -- Defense-in-depth smoke test (CORE-6 acceptance 5): a cyclic graph
    //    injected by direct internal manipulation (bypassing build()) must
    //    not hang or overflow expand_role; the visited set bounds the walk.

    #[test]
    fn expand_role_terminates_on_injected_cycle() {
        let mut roles = BTreeMap::new();
        roles.insert(
            role_name("a"),
            Role::new(role_name("a"), vec![scope("x.one")], vec![role_name("b")], ""),
        );
        roles.insert(
            role_name("b"),
            Role::new(role_name("b"), vec![scope("y.one")], vec![role_name("a")], ""),
        );
        // Direct struct construction — possible only inside the crate; the
        // builder (the only public path) rejects this shape. AUTHZ-CORE-4's
        // build()-time rejection is the primary defense; this is layered.
        let reg = ScopeRegistry {
            roles,
            public_methods: BTreeSet::new(),
            method_overlays: BTreeMap::new(),
        };
        assert_eq!(
            reg.expand_role(&role_name("a")),
            BTreeSet::from([scope("x.one"), scope("y.one")])
        );
    }
}
