//! AUTH-2: **grants, roles, memberships, ceilings — and the gate** that asks
//! them on every call.
//!
//! The model (AUTH-1, owner 2026-10-10: "every method should be its own grant
//! inherently and require a role to have it explicitly listed if not admin
//! role"):
//!
//! - A [`Grant`] is the right to call one method: `<activation>.<method>`
//!   (`tickets.set_status`). Inherent — every method has exactly one and
//!   nothing declares it.
//! - A role is a named, explicit list of grants ([`GrantSet::Listed`]); the
//!   built-in [`ADMIN`] role alone holds every grant ([`GrantSet::All`]).
//!   [`RoleTable`] is an in-memory [`Roles`] in which a role may list
//!   another role (inclusion), flattened as it is defined.
//! - A [`Membership`] says a principal holds a role on a scope
//!   ([`ScopeRef::Named`]) or everywhere ([`ScopeRef::Everywhere`], `*`).
//! - A *target* is the param that locates the resource a call acts on; the
//!   service's [`Resolve`] maps its value to the scopes it lives in,
//!   innermost first (`MENGER-12` → `[MENGER, *]`).
//! - A [`Ceiling`] is a session's upper bound (IDENTITY-40): `role@SCOPE` or
//!   `grant@SCOPE` entries. A session may carry several layers; every layer
//!   must allow a check, as the memberships must.
//!
//! [`Gate::check`] answers one call: allowed — with the [`Reach`] the method
//! answers from — or a [`Refusal`] that names what was needed. Everything is
//! answered from memory: the three service traits are synchronous and must
//! not do I/O.
//!
//! # Relation to R-5's [`ScopeRegistry`](crate::ScopeRegistry)
//!
//! R-5's registry maps *token-claimed roles* to dotted capability scopes and
//! knows nothing of where a role is held. The grant model keeps its words —
//! a grant is exactly R-5's implicit `<activation>.<method>` scope, and
//! [`RoleName`] is the same type — and adds the *where*: memberships on
//! scopes, targets resolved through a chain, ceilings. Both gates can be
//! configured on one hub; a hub with neither dispatches as before.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::audit::RoleName;
use crate::auth::AuthContext;
use crate::identity::Principal;

/// The built-in role that holds every grant. No other role holds anything it
/// does not list.
pub const ADMIN: &str = "admin";

/// The metadata key a session's ceiling rides under (IDENTITY-42's
/// `menger_session` sessions write it): either a list of `role@SCOPE` /
/// `grant@SCOPE` strings (one layer) or a list of such lists (layers, every
/// one of which must allow a check).
pub const CEILING_KEY: &str = "ceiling";

// ---------------------------------------------------------------------------
// Grant
// ---------------------------------------------------------------------------

/// The right to call one method: `<activation>.<method>`, e.g.
/// `tickets.set_status`. Every method has exactly one; nothing declares it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Grant(String);

impl Grant {
    /// Wrap a dotted method path as a grant. Unvalidated, as wire-decoded
    /// values are.
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// The grant of `method` on `activation`: `<activation>.<method>`.
    pub fn of(activation: &str, method: &str) -> Self {
        Self(format!("{activation}.{method}"))
    }

    /// The dotted path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Grant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// ScopeRef
// ---------------------------------------------------------------------------

/// Where a role is held: everywhere (`*`) or one named scope (`MENGER`).
/// What a name means — a shortcode, a tenant, a project — is the service's;
/// the gate only compares names and asks [`Resolve::chain`] how they nest.
///
/// On the wire, a plain string: `"*"` or the name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScopeRef {
    /// `*`: every scope.
    Everywhere,
    /// One named scope, and whatever the service nests under it.
    Named(String),
}

impl ScopeRef {
    /// `"*"` → [`ScopeRef::Everywhere`]; anything else (trimmed) → named.
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "*" => Self::Everywhere,
            other => Self::Named(other.to_string()),
        }
    }

    /// A named scope.
    pub fn named(name: impl Into<String>) -> Self {
        Self::Named(name.into())
    }

    /// `"*"` or the name.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Everywhere => "*",
            Self::Named(n) => n,
        }
    }

    /// Whether this is `*`.
    pub fn is_everywhere(&self) -> bool {
        matches!(self, Self::Everywhere)
    }
}

impl fmt::Display for ScopeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ScopeRef {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ScopeRef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self::parse(&s))
    }
}

// ---------------------------------------------------------------------------
// GrantSet, RoleOrGrant, Membership, Ceiling
// ---------------------------------------------------------------------------

/// What a role holds: every grant ([`ADMIN`]) or exactly those it lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantSet {
    /// Every grant — the admin role, and only it by default.
    All,
    /// Exactly these grants.
    Listed(BTreeSet<Grant>),
}

impl GrantSet {
    /// Whether the set holds `grant`.
    pub fn contains(&self, grant: &Grant) -> bool {
        match self {
            Self::All => true,
            Self::Listed(set) => set.contains(grant),
        }
    }

    /// A listed set from anything that names grants.
    pub fn listed<I, G>(grants: I) -> Self
    where
        I: IntoIterator<Item = G>,
        G: Into<String>,
    {
        Self::Listed(grants.into_iter().map(|g| Grant::new(g)).collect())
    }
}

/// One ceiling entry's left side: a role (`editor`) or a single grant
/// (`tickets.get`). A dotted name is a grant; a bare one is a role.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RoleOrGrant {
    Role(RoleName),
    Grant(Grant),
}

impl RoleOrGrant {
    /// A dotted name is a grant, a bare one a role.
    pub fn parse(text: &str) -> Self {
        let t = text.trim();
        if t.contains('.') {
            Self::Grant(Grant::new(t))
        } else {
            Self::Role(RoleName::new(t))
        }
    }
}

impl fmt::Display for RoleOrGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Role(r) => write!(f, "{r}"),
            Self::Grant(g) => write!(f, "{g}"),
        }
    }
}

/// A principal holds a role on a scope: `key:ac79… is editor on MENGER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub principal: Principal,
    pub role: RoleName,
    pub scope: ScopeRef,
}

/// A session's upper bound (IDENTITY-40): `(role or grant, scope)` entries,
/// spelled `editor@MENGER-12`, `tickets.get@*`. A check passes a ceiling
/// when some entry's scope is in the target's chain and the entry allows the
/// grant (the grant itself, or a role listing it).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ceiling(pub Vec<(RoleOrGrant, ScopeRef)>);

/// Why a ceiling could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeilingError(pub String);

impl fmt::Display for CeilingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CeilingError {}

impl Ceiling {
    /// One `role@SCOPE` or `grant@SCOPE` entry.
    pub fn entry(text: &str) -> Result<(RoleOrGrant, ScopeRef), CeilingError> {
        let (left, scope) = text
            .trim()
            .split_once('@')
            .ok_or_else(|| CeilingError(format!("`{}` is not role@SCOPE or grant@SCOPE", text.trim())))?;
        if left.trim().is_empty() || scope.trim().is_empty() {
            return Err(CeilingError(format!("`{}` is not role@SCOPE or grant@SCOPE", text.trim())));
        }
        Ok((RoleOrGrant::parse(left), ScopeRef::parse(scope)))
    }

    /// A ceiling from its entries' text.
    pub fn parse<I, S>(entries: I) -> Result<Self, CeilingError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        entries
            .into_iter()
            .map(|e| Self::entry(e.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map(Ceiling)
    }

    /// The entries as the wire says them: `role@SCOPE` each.
    pub fn text(&self) -> Vec<String> {
        self.0.iter().map(|(rg, s)| format!("{rg}@{s}")).collect()
    }

    /// The ceilings an identity's metadata carries under [`CEILING_KEY`]:
    /// none → `[]`; a list of strings → one layer; a list of lists → one
    /// layer each. Anything else is an error, and a caller whose ceiling
    /// cannot be read must be refused, never widened.
    pub fn layers_of(ctx: &AuthContext) -> Result<Vec<Ceiling>, CeilingError> {
        let Some(v) = ctx.metadata.get(CEILING_KEY) else {
            return Ok(Vec::new());
        };
        let unreadable = || CeilingError("this session's ceiling cannot be read: sign in again".into());
        let items = v.as_array().ok_or_else(unreadable)?;
        if items.iter().all(|i| i.is_string()) {
            let texts: Vec<&str> = items.iter().filter_map(|i| i.as_str()).collect();
            return Ok(vec![Self::parse(texts).map_err(|_| unreadable())?]);
        }
        items
            .iter()
            .map(|layer| {
                let entries = layer.as_array().ok_or_else(unreadable)?;
                let texts = entries
                    .iter()
                    .map(|e| e.as_str().ok_or_else(unreadable))
                    .collect::<Result<Vec<_>, _>>()?;
                Self::parse(texts).map_err(|_| unreadable())
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// What a service supplies
// ---------------------------------------------------------------------------

/// Who holds which role where (menger: its members table, cached). Answered
/// from memory: no I/O on a call.
pub trait Memberships: Send + Sync {
    fn held(&self, who: &Principal) -> Vec<Membership>;
}

/// Role → grants (defaults declared in code, edits as data). Answered from
/// memory. [`ADMIN`] holds every grant whatever this answers.
pub trait Roles: Send + Sync {
    /// What `role` holds; `None` for a role this service does not know
    /// (it holds nothing).
    fn grants(&self, role: &RoleName) -> Option<GrantSet>;

    /// Every role this service knows, so a refusal can name the roles that
    /// list a grant. The default knows none (a refusal then names only
    /// [`ADMIN`]).
    fn names(&self) -> Vec<RoleName> {
        Vec::new()
    }
}

/// Where a target lives. Answered from memory.
pub trait Resolve: Send + Sync {
    /// The scopes a target lives in, innermost first, ending in
    /// [`ScopeRef::Everywhere`]: `"MENGER-12"` → `[MENGER-12, MENGER, *]`
    /// (or, for a service whose memberships are per shortcode,
    /// `[MENGER, *]`). `None`: the value locates nothing — the call is
    /// refused.
    ///
    /// The gate also asks it about **scope names** (a membership's or a
    /// ceiling's): `chain("MENGER")` → `[MENGER, PLEXUS, *]`, to tell which
    /// of two scopes lies within the other when it narrows a reach by a
    /// ceiling. A service that cannot answer for a name returns `None`, and
    /// two different names are then taken as disjoint.
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>>;
}

// ---------------------------------------------------------------------------
// RoleTable — an in-memory Roles with inclusion
// ---------------------------------------------------------------------------

/// Why [`RoleTable::define`] refused a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleTableError {
    /// An entry named a role that is not (yet) defined. A role may only
    /// include roles defined before it, which is what keeps inclusion
    /// acyclic.
    UnknownRole { role: String, includes: String },
}

impl fmt::Display for RoleTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRole { role, includes } => write!(
                f,
                "role {role} includes {includes}, which is not defined before it"
            ),
        }
    }
}

impl std::error::Error for RoleTableError {}

/// An in-memory [`Roles`]: each role an explicit list of grants, where an
/// entry may also name an earlier role (inclusion, flattened when defined).
/// [`ADMIN`] is built in.
///
/// ```
/// use plexus_auth_core::grants::{Grant, RoleTable, Roles};
/// use plexus_auth_core::RoleName;
///
/// let roles = RoleTable::new()
///     .define("viewer", ["tickets.get", "tickets.list"]).unwrap()
///     .define("editor", ["viewer", "tickets.set_status"]).unwrap();
/// let editor = roles.grants(&RoleName::new("editor")).unwrap();
/// assert!(editor.contains(&Grant::new("tickets.get")));
/// ```
#[derive(Debug, Clone, Default)]
pub struct RoleTable {
    roles: BTreeMap<RoleName, GrantSet>,
}

impl RoleTable {
    /// The table with only the built-in [`ADMIN`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Define (or extend) `role`: each entry a grant (dotted) or an earlier
    /// role (bare), whose grants are included. Defining a role again adds to
    /// it, which is how several activations' defaults for one role name
    /// merge.
    pub fn define<I, S>(mut self, role: &str, entries: I) -> Result<Self, RoleTableError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let name = RoleName::new(role);
        let mut set = match self.roles.remove(&name) {
            Some(GrantSet::Listed(s)) => s,
            Some(GrantSet::All) => {
                self.roles.insert(name, GrantSet::All);
                return Ok(self);
            }
            None => BTreeSet::new(),
        };
        let mut all = name.as_str() == ADMIN;
        for entry in entries {
            let e = entry.as_ref().trim();
            if e.contains('.') {
                set.insert(Grant::new(e));
                continue;
            }
            if e == ADMIN {
                all = true;
                continue;
            }
            match self.roles.get(&RoleName::new(e)) {
                Some(GrantSet::All) => all = true,
                Some(GrantSet::Listed(inc)) => set.extend(inc.iter().cloned()),
                None => {
                    return Err(RoleTableError::UnknownRole { role: role.to_string(), includes: e.to_string() })
                }
            }
        }
        self.roles.insert(name, if all { GrantSet::All } else { GrantSet::Listed(set) });
        Ok(self)
    }

    /// Replace `role`'s grants outright (an admin's edit: the store wins).
    pub fn set(&mut self, role: &str, grants: GrantSet) {
        self.roles.insert(RoleName::new(role), grants);
    }

    /// A table from already-flat lists (`role → [grant, …]`), as a schema's
    /// `roles` carries them; lists for one role name merge.
    pub fn from_lists<'a, I, G>(lists: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, G)>,
        G: IntoIterator,
        G::Item: AsRef<str>,
    {
        let mut table = Self::new();
        for (role, grants) in lists {
            let name = RoleName::new(role);
            let grants: Vec<Grant> = grants.into_iter().map(|g| Grant::new(g.as_ref().trim())).collect();
            match table.roles.entry(name) {
                std::collections::btree_map::Entry::Occupied(mut o) => {
                    if let GrantSet::Listed(s) = o.get_mut() {
                        s.extend(grants);
                    }
                }
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(if role == ADMIN { GrantSet::All } else { GrantSet::Listed(grants.into_iter().collect()) });
                }
            }
        }
        table
    }
}

impl Roles for RoleTable {
    fn grants(&self, role: &RoleName) -> Option<GrantSet> {
        if role.as_str() == ADMIN {
            return Some(GrantSet::All);
        }
        self.roles.get(role).cloned()
    }

    fn names(&self) -> Vec<RoleName> {
        self.roles.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Refusal
// ---------------------------------------------------------------------------

/// Why the gate refused a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No principal: only `public` methods are reachable anonymously.
    Unauthenticated,
    /// The caller does not hold `grant` on `scope` (within its ceiling).
    MissingGrant {
        /// The grant the call needed.
        grant: Grant,
        /// Where it was needed: the target's innermost scope, or `*` for a
        /// method without a target (held anywhere would have done).
        scope: ScopeRef,
        /// The roles that list the grant ([`ADMIN`] last).
        roles: Vec<RoleName>,
        /// Where the caller does hold it (within its ceiling).
        held_on: Vec<ScopeRef>,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("sign in first"),
            Self::MissingGrant { grant, scope, .. } => write!(f, "needs {grant} on {scope}"),
        }
    }
}

impl std::error::Error for Refusal {}

// ---------------------------------------------------------------------------
// Reach
// ---------------------------------------------------------------------------

/// Where a call may act: the scopes the caller holds the method's grant on
/// (within its ceiling), handed to the method beside `auth`. A read without a
/// target (`list`, `watch`) answers only from these.
///
/// A reach is **live** when it came from a gate: [`Reach::allows`] and
/// [`Reach::current`] ask the gate again, as memberships, roles and the
/// ceiling stand *now* — so a stream checks each event (IDENTITY-37: a role
/// revoked reaches an open stream at its next event). A hub without a gate
/// hands every method [`Reach::everywhere`], which allows everything.
#[derive(Clone)]
pub struct Reach {
    held_on: Vec<ScopeRef>,
    live: Option<Live>,
}

#[derive(Clone)]
struct Live {
    gate: Gate,
    caller: Option<AuthContext>,
    grant: Grant,
}

impl fmt::Debug for Reach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reach")
            .field("held_on", &self.held_on)
            .field("grant", &self.live.as_ref().map(|l| l.grant.as_str()))
            .finish()
    }
}

impl PartialEq for Reach {
    /// Two reaches are equal when they hold the same scopes for the same
    /// grant (the gate behind them is not compared).
    fn eq(&self, other: &Self) -> bool {
        self.held_on == other.held_on && self.grant() == other.grant()
    }
}

impl Reach {
    /// Everything — what a method receives on a hub without a gate (login
    /// off), as today.
    pub fn everywhere() -> Self {
        Self { held_on: vec![ScopeRef::Everywhere], live: None }
    }

    /// Whether the grant is held on `*`.
    pub fn is_everywhere(&self) -> bool {
        self.held_on.iter().any(ScopeRef::is_everywhere)
    }

    /// Whether the grant is held nowhere (a `public` method called by a
    /// caller who holds no role listing it).
    pub fn is_empty(&self) -> bool {
        self.held_on.is_empty()
    }

    /// The scopes the grant is held on; `[*]` when everywhere.
    pub fn held_on(&self) -> &[ScopeRef] {
        &self.held_on
    }

    /// The grant this reach is for; `None` on a hub without a gate.
    pub fn grant(&self) -> Option<&Grant> {
        self.live.as_ref().map(|l| &l.grant)
    }

    /// Whether the call may act on `target` — asked of the gate as it
    /// stands now. Without a gate: always.
    pub fn allows(&self, target: &str) -> bool {
        match &self.live {
            None => self.is_everywhere(),
            Some(l) => l.gate.check(l.caller.as_ref(), &l.grant, Some(target)).is_ok(),
        }
    }

    /// The reach as it stands now: `None` once the grant is held nowhere (a
    /// stream should end). Without a gate: unchanged.
    pub fn current(&self) -> Option<Reach> {
        match &self.live {
            None => Some(self.clone()),
            Some(l) => l.gate.check(l.caller.as_ref(), &l.grant, None).ok(),
        }
    }

    /// Whether the reach covers a target whose chain is `chain` (as
    /// [`Resolve::chain`] gives it), by this snapshot — no new question to
    /// the gate. Prefer [`Reach::allows`] where the answer must be current.
    pub fn covers(&self, chain: &[ScopeRef]) -> bool {
        self.is_everywhere() || self.held_on.iter().any(|s| chain.contains(s))
    }
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

struct GateInner {
    memberships: Arc<dyn Memberships>,
    roles: Arc<dyn Roles>,
    resolve: Arc<dyn Resolve>,
}

/// The one rule in front of every call: the method's grant, held through a
/// role on the target's scope, within the session's ceiling. Default deny.
/// Cheap to clone (one `Arc`); cheap to ask (memory only), so a stream may
/// ask per event.
#[derive(Clone)]
pub struct Gate {
    inner: Arc<GateInner>,
}

impl fmt::Debug for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gate")
    }
}

impl Gate {
    /// A gate over a service's memberships, roles and resolver.
    pub fn new(memberships: Arc<dyn Memberships>, roles: Arc<dyn Roles>, resolve: Arc<dyn Resolve>) -> Self {
        Self { inner: Arc::new(GateInner { memberships, roles, resolve }) }
    }

    /// Whether `role` lists `grant` ([`ADMIN`] lists every grant).
    pub fn lists(&self, role: &RoleName, grant: &Grant) -> bool {
        role.as_str() == ADMIN || self.inner.roles.grants(role).is_some_and(|g| g.contains(grant))
    }

    /// The roles that list `grant`, [`ADMIN`] last.
    pub fn roles_listing(&self, grant: &Grant) -> Vec<RoleName> {
        let mut out: Vec<RoleName> = self
            .inner
            .roles
            .names()
            .into_iter()
            .filter(|r| r.as_str() != ADMIN && self.lists(r, grant))
            .collect();
        out.push(RoleName::new(ADMIN));
        out
    }

    /// Whether a ceiling entry allows `grant`.
    fn entry_allows(&self, entry: &RoleOrGrant, grant: &Grant) -> bool {
        match entry {
            RoleOrGrant::Grant(g) => g == grant,
            RoleOrGrant::Role(r) => self.lists(r, grant),
        }
    }

    /// The caller's principal and ceiling layers; `None` when anonymous. An
    /// unreadable ceiling becomes one empty layer — it allows nothing.
    fn caller_of(caller: Option<&AuthContext>) -> Option<(Principal, Vec<Ceiling>)> {
        let ctx = caller?;
        let principal = ctx.principal()?;
        let layers = Ceiling::layers_of(ctx).unwrap_or_else(|_| vec![Ceiling::default()]);
        Some((principal, layers))
    }

    /// Whether `inner` lies within `outer` (or is it).
    fn within(&self, inner: &ScopeRef, outer: &ScopeRef) -> bool {
        if outer.is_everywhere() || inner == outer {
            return true;
        }
        match inner {
            ScopeRef::Everywhere => false,
            ScopeRef::Named(name) => self.inner.resolve.chain(name).is_some_and(|c| c.contains(outer)),
        }
    }

    /// The scopes both `a` and `b` reach: where one lies within the other,
    /// the inner one.
    fn meet(&self, a: Vec<ScopeRef>, b: Vec<ScopeRef>) -> Vec<ScopeRef> {
        if a.iter().any(ScopeRef::is_everywhere) {
            return b;
        }
        if b.iter().any(ScopeRef::is_everywhere) {
            return a;
        }
        let mut out = BTreeSet::new();
        for x in &a {
            for y in &b {
                if self.within(x, y) {
                    out.insert(x.clone());
                } else if self.within(y, x) {
                    out.insert(y.clone());
                }
            }
        }
        out.into_iter().collect()
    }

    /// Collapse to `[*]` when `*` is among them; dedupe, ordered.
    fn normal(scopes: impl IntoIterator<Item = ScopeRef>) -> Vec<ScopeRef> {
        let set: BTreeSet<ScopeRef> = scopes.into_iter().collect();
        if set.contains(&ScopeRef::Everywhere) {
            vec![ScopeRef::Everywhere]
        } else {
            set.into_iter().collect()
        }
    }

    fn held_on_for(&self, principal: &Principal, layers: &[Ceiling], grant: &Grant) -> Vec<ScopeRef> {
        let mut acc = Self::normal(
            self.inner
                .memberships
                .held(principal)
                .into_iter()
                .filter(|m| self.lists(&m.role, grant))
                .map(|m| m.scope),
        );
        for layer in layers {
            if acc.is_empty() {
                break;
            }
            let allowed = Self::normal(
                layer.0.iter().filter(|(rg, _)| self.entry_allows(rg, grant)).map(|(_, s)| s.clone()),
            );
            acc = self.meet(acc, allowed);
        }
        acc
    }

    /// Where the caller holds `grant`, within its ceiling: `[*]` when
    /// everywhere, `[]` when nowhere (and for an anonymous caller). What a
    /// method without a target answers from.
    pub fn held_on(&self, caller: &AuthContext, grant: &Grant) -> Vec<ScopeRef> {
        match Self::caller_of(Some(caller)) {
            Some((p, layers)) => self.held_on_for(&p, &layers, grant),
            None => Vec::new(),
        }
    }

    /// Allowed when the grant is listed by a role held on a scope in the
    /// target's chain — or anywhere, for a call with no target — and every
    /// ceiling layer allows it the same way. The [`Reach`] is live (it asks
    /// this gate again on [`Reach::allows`] / [`Reach::current`]).
    pub fn check(&self, caller: Option<&AuthContext>, grant: &Grant, target: Option<&str>) -> Result<Reach, Refusal> {
        let Some((principal, layers)) = Self::caller_of(caller) else {
            return Err(Refusal::Unauthenticated);
        };
        let held_on = self.held_on_for(&principal, &layers, grant);
        let (allowed, scope) = match target {
            None => (!held_on.is_empty(), ScopeRef::Everywhere),
            Some(t) => match self.inner.resolve.chain(t) {
                None => (false, ScopeRef::named(t)),
                Some(chain) => {
                    let in_chain = |s: &ScopeRef| s.is_everywhere() || chain.contains(s);
                    let by_membership = self
                        .inner
                        .memberships
                        .held(&principal)
                        .iter()
                        .any(|m| in_chain(&m.scope) && self.lists(&m.role, grant));
                    let by_ceiling = layers
                        .iter()
                        .all(|layer| layer.0.iter().any(|(rg, s)| in_chain(s) && self.entry_allows(rg, grant)));
                    let scope = chain.first().cloned().unwrap_or_else(|| ScopeRef::named(t));
                    (by_membership && by_ceiling, scope)
                }
            },
        };
        if allowed {
            Ok(Reach {
                held_on,
                live: Some(Live { gate: self.clone(), caller: caller.cloned(), grant: grant.clone() }),
            })
        } else {
            Err(Refusal::MissingGrant { grant: grant.clone(), scope, roles: self.roles_listing(grant), held_on })
        }
    }

    /// The reach of a `public` method: what [`Gate::check`] would allow
    /// without a target, or an empty (still live) reach when the caller holds
    /// the grant nowhere or is anonymous. A public method is never refused.
    pub fn reach_of_public(&self, caller: Option<&AuthContext>, grant: &Grant) -> Reach {
        self.check(caller, grant, None).unwrap_or_else(|_| Reach {
            held_on: Vec::new(),
            live: Some(Live { gate: self.clone(), caller: caller.cloned(), grant: grant.clone() }),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests — the gate's decision table
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Memberships as a mutable table, so a test can revoke one.
    #[derive(Default)]
    struct Members(Mutex<Vec<Membership>>);
    impl Members {
        fn grant(&self, who: &str, role: &str, scope: &str) {
            self.0.lock().unwrap().push(Membership {
                principal: who.parse().unwrap(),
                role: RoleName::new(role),
                scope: ScopeRef::parse(scope),
            });
        }
        fn revoke_all(&self) {
            self.0.lock().unwrap().clear();
        }
    }
    impl Memberships for Members {
        fn held(&self, who: &Principal) -> Vec<Membership> {
            self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
        }
    }

    /// menger-shaped: a ticket `CODE-n` lives in itself, then `CODE`;
    /// MENGER and IDENTITY are disjoint, both hosted under PLEXUS.
    struct Shortcodes;
    impl Resolve for Shortcodes {
        fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
            let code = target.split_once('-').map(|(c, _)| c).unwrap_or(target);
            let mut chain = Vec::new();
            if target.contains('-') {
                chain.push(ScopeRef::named(target));
            }
            match code {
                "MENGER" | "IDENTITY" => {
                    chain.push(ScopeRef::named(code));
                    chain.push(ScopeRef::named("PLEXUS"));
                }
                "PLEXUS" => chain.push(ScopeRef::named("PLEXUS")),
                _ => return None,
            }
            chain.push(ScopeRef::Everywhere);
            Some(chain)
        }
    }

    fn roles() -> RoleTable {
        RoleTable::new()
            .define("viewer", ["tickets.get", "tickets.list"])
            .unwrap()
            .define("editor", ["viewer", "tickets.set_status"])
            .unwrap()
    }

    fn gate(members: &Arc<Members>) -> Gate {
        Gate::new(members.clone(), Arc::new(roles()), Arc::new(Shortcodes))
    }

    fn who(p: &str) -> AuthContext {
        AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], serde_json::Value::Null)
    }

    fn with_ceiling(p: &str, ceiling: serde_json::Value) -> AuthContext {
        AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], serde_json::json!({ CEILING_KEY: ceiling }))
    }

    fn g(s: &str) -> Grant {
        Grant::new(s)
    }

    #[test]
    fn a_grant_no_role_lists_is_refused_to_all_but_admin() {
        let m = Arc::new(Members::default());
        m.grant(ADA, "editor", "*");
        m.grant(BOB, "admin", "MENGER");
        let gate = gate(&m);
        let err = gate.check(Some(&who(ADA)), &g("members.grant"), Some("MENGER-1")).unwrap_err();
        assert_eq!(
            err,
            Refusal::MissingGrant {
                grant: g("members.grant"),
                scope: ScopeRef::named("MENGER-1"),
                roles: vec![RoleName::new("admin")],
                held_on: vec![],
            }
        );
        assert!(gate.check(Some(&who(BOB)), &g("members.grant"), Some("MENGER-1")).is_ok());
        // admin on MENGER is not admin on IDENTITY.
        assert!(gate.check(Some(&who(BOB)), &g("members.grant"), Some("IDENTITY-1")).is_err());
    }

    #[test]
    fn held_on_a_scope_allows_targets_in_its_chain_only() {
        let m = Arc::new(Members::default());
        m.grant(ADA, "editor", "MENGER");
        let gate = gate(&m);
        let reach = gate.check(Some(&who(ADA)), &g("tickets.set_status"), Some("MENGER-12")).unwrap();
        assert_eq!(reach.held_on(), &[ScopeRef::named("MENGER")]);
        let err = gate.check(Some(&who(ADA)), &g("tickets.set_status"), Some("IDENTITY-1")).unwrap_err();
        assert_eq!(
            err,
            Refusal::MissingGrant {
                grant: g("tickets.set_status"),
                scope: ScopeRef::named("IDENTITY-1"),
                roles: vec![RoleName::new("editor"), RoleName::new("admin")],
                held_on: vec![ScopeRef::named("MENGER")],
            }
        );
        assert_eq!(err.to_string(), "needs tickets.set_status on IDENTITY-1");
        // A target nothing resolves is refused.
        assert!(gate.check(Some(&who(ADA)), &g("tickets.get"), Some("NOPE-1")).is_err());
    }

    #[test]
    fn held_on_everywhere_allows_any_target_and_reach_is_everywhere() {
        let m = Arc::new(Members::default());
        m.grant(ADA, "viewer", "*");
        m.grant(ADA, "viewer", "MENGER");
        let gate = gate(&m);
        let reach = gate.check(Some(&who(ADA)), &g("tickets.get"), Some("IDENTITY-3")).unwrap();
        assert!(reach.is_everywhere());
        assert_eq!(reach.held_on(), &[ScopeRef::Everywhere]);
        assert!(gate.check(Some(&who(ADA)), &g("tickets.list"), None).unwrap().is_everywhere());
        // viewer does not list set_status, wherever it is held.
        assert!(gate.check(Some(&who(ADA)), &g("tickets.set_status"), Some("IDENTITY-3")).is_err());
    }

    #[test]
    fn without_a_target_held_anywhere_suffices_and_reach_says_where() {
        let m = Arc::new(Members::default());
        m.grant(ADA, "viewer", "MENGER");
        m.grant(ADA, "viewer", "IDENTITY");
        let gate = gate(&m);
        let reach = gate.check(Some(&who(ADA)), &g("tickets.list"), None).unwrap();
        assert_eq!(reach.held_on(), &[ScopeRef::named("IDENTITY"), ScopeRef::named("MENGER")]);
        assert!(reach.allows("MENGER-4"));
        assert!(!reach.allows("PLEXUS-1"));
        let err = gate.check(Some(&who(BOB)), &g("tickets.list"), None).unwrap_err();
        assert!(matches!(err, Refusal::MissingGrant { ref scope, .. } if scope.is_everywhere()));
    }

    #[test]
    fn a_ceiling_narrows_the_membership() {
        let m = Arc::new(Members::default());
        m.grant(ADA, "editor", "MENGER");
        let gate = gate(&m);
        let narrowed = with_ceiling(ADA, serde_json::json!(["editor@MENGER-12"]));
        assert!(gate.check(Some(&narrowed), &g("tickets.set_status"), Some("MENGER-12")).is_ok());
        assert!(gate.check(Some(&narrowed), &g("tickets.set_status"), Some("MENGER-13")).is_err());
        // The reach of a target-less read is the meet: MENGER-12, inside MENGER.
        let reach = gate.check(Some(&narrowed), &g("tickets.list"), None).unwrap();
        assert_eq!(reach.held_on(), &[ScopeRef::named("MENGER-12")]);
        // A grant-entry ceiling: only tickets.get, anywhere the membership allows.
        let only_get = with_ceiling(ADA, serde_json::json!([["tickets.get@*"]]));
        assert!(gate.check(Some(&only_get), &g("tickets.get"), Some("MENGER-1")).is_ok());
        let err = gate.check(Some(&only_get), &g("tickets.set_status"), Some("MENGER-1")).unwrap_err();
        assert!(matches!(err, Refusal::MissingGrant { ref held_on, .. } if held_on.is_empty()));
        // Two layers: both must allow.
        let layered = with_ceiling(ADA, serde_json::json!([["editor@*"], ["viewer@MENGER"]]));
        assert!(gate.check(Some(&layered), &g("tickets.get"), Some("MENGER-1")).is_ok());
        assert!(gate.check(Some(&layered), &g("tickets.set_status"), Some("MENGER-1")).is_err());
        // A ceiling never widens: editor@IDENTITY grants nothing there.
        let wider = with_ceiling(ADA, serde_json::json!(["editor@IDENTITY"]));
        assert!(gate.check(Some(&wider), &g("tickets.get"), Some("IDENTITY-1")).is_err());
        // An unreadable ceiling allows nothing.
        let bad = with_ceiling(ADA, serde_json::json!("editor@*"));
        assert!(gate.check(Some(&bad), &g("tickets.get"), Some("MENGER-1")).is_err());
    }

    #[test]
    fn role_inclusion_flattens_and_must_name_an_earlier_role() {
        let r = roles();
        let editor = r.grants(&RoleName::new("editor")).unwrap();
        assert!(editor.contains(&g("tickets.get")) && editor.contains(&g("tickets.set_status")));
        let viewer = r.grants(&RoleName::new("viewer")).unwrap();
        assert!(!viewer.contains(&g("tickets.set_status")));
        assert_eq!(
            RoleTable::new().define("editor", ["viewer"]).unwrap_err(),
            RoleTableError::UnknownRole { role: "editor".into(), includes: "viewer".into() }
        );
        // admin is built in: holds every grant, whatever the table says.
        assert_eq!(r.grants(&RoleName::new("admin")), Some(GrantSet::All));
        // from_lists merges one role's lists from several activations.
        let merged = RoleTable::from_lists([("editor", vec!["tickets.get"]), ("editor", vec!["comments.add"])]);
        let e = merged.grants(&RoleName::new("editor")).unwrap();
        assert!(e.contains(&g("tickets.get")) && e.contains(&g("comments.add")));
    }

    #[test]
    fn anonymous_is_unauthenticated() {
        let m = Arc::new(Members::default());
        let gate = gate(&m);
        assert_eq!(gate.check(None, &g("tickets.get"), Some("MENGER-1")).unwrap_err(), Refusal::Unauthenticated);
        assert_eq!(
            gate.check(Some(&AuthContext::anonymous()), &g("tickets.list"), None).unwrap_err(),
            Refusal::Unauthenticated
        );
        // A public method's reach for an anonymous caller: empty, never refused.
        assert!(gate.reach_of_public(None, &g("auth.login")).is_empty());
    }

    #[test]
    fn a_live_reach_follows_grants_as_they_stand() {
        let m = Arc::new(Members::default());
        m.grant(ADA, "viewer", "MENGER");
        let gate = gate(&m);
        let reach = gate.check(Some(&who(ADA)), &g("tickets.list"), None).unwrap();
        assert!(reach.allows("MENGER-1"));
        assert!(reach.current().is_some());
        m.revoke_all();
        assert!(!reach.allows("MENGER-1"));
        assert!(reach.current().is_none());
        // Without a gate, everything.
        assert!(Reach::everywhere().allows("ANY-1") && Reach::everywhere().current().is_some());
    }

    #[test]
    fn scope_refs_and_ceilings_round_trip() {
        assert_eq!(serde_json::to_string(&ScopeRef::Everywhere).unwrap(), "\"*\"");
        assert_eq!(serde_json::from_str::<ScopeRef>("\"MENGER\"").unwrap(), ScopeRef::named("MENGER"));
        let c = Ceiling::parse(["editor@MENGER-12", "tickets.get@*"]).unwrap();
        assert_eq!(c.0[0], (RoleOrGrant::Role(RoleName::new("editor")), ScopeRef::named("MENGER-12")));
        assert_eq!(c.0[1], (RoleOrGrant::Grant(g("tickets.get")), ScopeRef::Everywhere));
        assert_eq!(c.text(), vec!["editor@MENGER-12", "tickets.get@*"]);
        assert!(Ceiling::parse(["editor"]).is_err());
    }
}
