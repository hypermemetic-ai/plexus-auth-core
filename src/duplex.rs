//! BIDIR-5 — the gate's rules for a duplex call, in this crate's terms.
//!
//! A duplex call is params, then an input half and an output half
//! (BIDIR-1). The gate decides it at open exactly as it decides any call
//! ([`Gate::check`](crate::grants::Gate::check): the method's grant on its
//! target, within the ceiling). What this module adds is what a duplex call
//! needs beyond that, each as data a method or a hub declares — no rule is
//! written in an application:
//!
//! | when | the gate does | in these terms |
//! |---|---|---|
//! | the call opens | [`Gate::check`](crate::grants::Gate::check), once; the call holds the caller and the [`Reach`](crate::grants::Reach) | a grant |
//! | an input frame arrives | no gate check: the frame's connection is the call's, the half is open, the grants generation is the one last verified, the frame is within credit and the [`CallCeiling`] | [`InputBy::Caller`], [`CallCeiling`] |
//! | the grants generation moves, a sign-out, the expiry | the caller verified again, once per call; a refusal closes the input half with `forbidden` / `unauthenticated` | a grant |
//! | a question is answered | [`Answerer`]: the caller's own connection; a person; or whoever holds a grant on the call's target | [`Answerer`] |
//! | a call goes into a client or a hub that dialed in | that peer's own gate, deciding for the principal on that connection — the other side of the call is a caller like any other | a grant on the peer |
//! | a call crosses a hop | [`hop_identity`]: the hop is the principal, the caller is named `for` and grants nothing, the hop's verdict is a ceiling layer; the far side decides again | a ceiling |

use serde_json::{json, Map, Value};

use crate::auth::{AuthContext, PRINCIPAL_CLAIM};
use crate::grants::{ScopeRef, CEILING_KEY};
use crate::identity::Issuer;

/// Who may send a call's input items. Only the caller, on the call's own
/// connection: an input item carries no target of its own, so there is
/// nothing another principal could be checked against. (A wider sender is
/// a second call, gated as one.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputBy {
    /// The connection that opened the call (`#[method(input_by = "caller")]`,
    /// the default and only form).
    #[default]
    Caller,
}

/// Who may answer a question a method asks mid-call — an output item that
/// expects a reply (BIDIR-1 `mechanism`). The method declares it
/// (`#[method(answer_by = "…")]`, BIDIR-1 `answerer`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Answerer {
    /// `caller` (default): the call's own connection, as the call's
    /// principal — whatever kind it is.
    #[default]
    Caller,
    /// `person`: the call's own connection, and its principal a person
    /// ([`is_person`]); an agent's answer is refused `person_required`.
    Person,
    /// `grant:<g>`: any connection whose principal holds grant `g` on the
    /// call's target (asked of the gate once, per answer) — the owner
    /// approving a step an agent's call asks.
    Grant(String),
}

impl Answerer {
    /// Read a declaration: `caller`, `person` or `grant:<dotted.grant>`.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim() {
            "caller" => Ok(Self::Caller),
            "person" => Ok(Self::Person),
            t => match t.strip_prefix("grant:") {
                Some(g) if g.contains('.') && !g.contains(char::is_whitespace) => Ok(Self::Grant(g.to_string())),
                _ => Err(format!("answer_by `{t}`: one of `caller`, `person`, `grant:<activation.method>`")),
            },
        }
    }
}

/// A person, as the identity's issuer vouches: a sign-in through plexus-idp
/// or an OIDC provider. A key, an API key or a nostr key is not (a nostr key
/// may be a person's, but nothing vouches it — AUTH-35 grades that).
pub fn is_person(ctx: &AuthContext) -> bool {
    ctx.principal().is_some_and(|p| matches!(p.issuer(), Issuer::Idp | Issuer::Oidc))
}

/// How much one call may take in (BIDIR-1: "every item that flows has a
/// limit"). Beside the transport's per-connection call count, which counts a
/// duplex call as one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallCeiling {
    /// Credit granted with the call's answer: items the caller may send
    /// before the callee grants more.
    pub credit: u64,
    /// Input items over the call's life.
    pub max_items: u64,
    /// Input bytes over the call's life (each item as its JSON).
    pub max_bytes: u64,
}

impl Default for CallCeiling {
    fn default() -> Self {
        Self { credit: 64, max_items: 1_000_000, max_bytes: 64 * 1024 * 1024 }
    }
}

/// The metadata key naming whom a hop acts for (IDENTITY-2's `for`;
/// RFC 8693's actor chain, read the other way): a list, nearest caller
/// first. It is attribution only — it grants nothing.
pub const FOR_KEY: &str = "for";

/// BIDIR-1 `forward` = identity: the context a call carries across a hop.
///
/// - the principal is the **hop** (`hop`: the calling hub's own identity on
///   the far side — its key, its session there);
/// - the caller is named under [`FOR_KEY`] (its principal, then whomever it
///   was itself acting for) and grants nothing;
/// - the hop's own ceilings and the caller's are kept, and the hop's **verdict** — the scopes
///   it admitted the caller on — is one more ceiling layer
///   (`admin@<scope>` each: any grant, only there), so the far side can
///   only narrow: the smaller of the two;
/// - nothing of the caller's credential crosses: not its session id, not
///   its metadata (tokens, session keys, proofs, its own ceilings).
///
/// The far side decides again, with its own gate, for the hop.
pub fn hop_identity(hop: &AuthContext, caller: &AuthContext, verdict: &[ScopeRef]) -> AuthContext {
    let mut meta = Map::new();
    for key in [PRINCIPAL_CLAIM, crate::auth::EXPIRES_AT_KEY] {
        if let Some(v) = hop.metadata.get(key) {
            meta.insert(key.into(), v.clone());
        }
    }
    let mut chain = vec![Value::String(caller.principal().map(|p| p.to_string()).unwrap_or_else(|| "anonymous".into()))];
    if let Some(Value::Array(earlier)) = caller.metadata.get(FOR_KEY) {
        chain.extend(earlier.iter().cloned());
    }
    meta.insert(FOR_KEY.into(), Value::Array(chain));
    // Ceilings are bounds, not credentials: the hop's own and the caller's
    // (one it carried across an earlier hop included) both stay, so a chain
    // only ever narrows. One that cannot be read is kept as written, and
    // the far side's gate refuses it, never widens it.
    let layers_of = |ctx: &AuthContext| -> Vec<Value> {
        match ctx.metadata.get(CEILING_KEY) {
            Some(Value::Array(items)) if items.iter().all(Value::is_string) => vec![Value::Array(items.clone())],
            Some(Value::Array(items)) => items.clone(),
            Some(other) => vec![other.clone()],
            None => Vec::new(),
        }
    };
    let mut layers = layers_of(hop);
    layers.extend(layers_of(caller));
    layers.push(Value::Array(verdict.iter().map(|s| json!(format!("{}@{s}", crate::grants::ADMIN))).collect()));
    meta.insert(CEILING_KEY.into(), Value::Array(layers));
    AuthContext::new(hop.user_id.clone(), hop.session_id.clone(), hop.roles.clone(), Value::Object(meta))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answerer_reads_its_declaration() {
        assert_eq!(Answerer::parse("caller"), Ok(Answerer::Caller));
        assert_eq!(Answerer::parse(" person "), Ok(Answerer::Person));
        assert_eq!(Answerer::parse("grant:runs.approve"), Ok(Answerer::Grant("runs.approve".into())));
        assert!(Answerer::parse("grant:approve").is_err());
        assert!(Answerer::parse("anyone").is_err());
        assert_eq!(Answerer::default(), Answerer::Caller);
    }
}
