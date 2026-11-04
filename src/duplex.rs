//! BIDIR-5 / BIDIR-8 — the gate's rules for a duplex call, in this crate's terms.
//!
//! A duplex call is params, then an input half and an output half
//! (BIDIR-1). The gate decides it at open exactly as it decides any call
//! ([`Gate::check`](crate::grants::Gate::check): the method's grant on its
//! target, within the ceiling). What this module adds is what a duplex call
//! needs beyond that, each as data a method or a service declares — no rule is
//! written in an application:
//!
//! | when | the gate does | in these terms |
//! |---|---|---|
//! | the call opens | [`Gate::check`](crate::grants::Gate::check), once; the call holds the caller and the [`Reach`](crate::grants::Reach) | a grant |
//! | an input frame arrives | no gate check: the frame's connection is the call's, the half is open, the grants generation is the one last verified, the frame is within credit and the [`CallCeiling`] | [`InputBy::Caller`], [`CallCeiling`] |
//! | the grants generation moves, a sign-out, the expiry | the caller verified again, once per call; a refusal closes the input half with `forbidden` / `unauthenticated` | a grant |
//! | a question is answered | [`Answerer`]: the caller's own connection; a person; or whoever holds a grant on the call's target | [`Answerer`] |
//! | a call goes into a client or a service that dialed in | that peer's own gate, deciding for the principal on that connection — the other side of the call is a caller like any other | a grant on the peer |
//! | a call crosses a hop | [`hop_identity`]: the hop is the principal, the caller is named `for` and grants nothing, the hop's verdict is a ceiling layer; the far side decides again | a ceiling |

use serde::{Deserialize, Serialize};
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

/// BIDIR-8: the spellings `#[method(answer_by = "…")]` takes, for a
/// refusal to name (the macro's compile error says the same three).
pub const ANSWER_BY_SPELLINGS: &str = "`caller` (the default), `person`, or `grant:<activation.method>`";

impl Answerer {
    /// BIDIR-8: the declaration as written (`MethodSchema.answer_by`):
    /// `None` for the default, so a method without one is unchanged.
    pub fn declared(&self) -> Option<String> {
        match self {
            Self::Caller => None,
            Self::Person => Some("person".into()),
            Self::Grant(g) => Some(format!("grant:{g}")),
        }
    }

    /// BIDIR-8: the answerer a schema names (`MethodSchema.answer_by`;
    /// absent is the default). A spelling the macro would have refused is
    /// an error, never a wider answerer.
    pub fn of_schema(answer_by: Option<&str>) -> Result<Self, String> {
        answer_by.map_or(Ok(Self::Caller), Self::parse)
    }

    /// Read a declaration: `caller`, `person` or `grant:<dotted.grant>`.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim() {
            "caller" => Ok(Self::Caller),
            "person" => Ok(Self::Person),
            t => match t.strip_prefix("grant:") {
                Some(g) if g.contains('.') && !g.contains(char::is_whitespace) => Ok(Self::Grant(g.to_string())),
                _ => Err(format!("answer_by `{t}`: one of {ANSWER_BY_SPELLINGS}")),
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

/// The credit a method grants unless it says otherwise
/// (`#[method(input_window = N)]`, BIDIR-6).
pub const DEFAULT_INPUT_WINDOW: u64 = 64;

/// The bytes one call may hold buffered unless it says otherwise
/// (`#[method(input_max_buffered = N)]`, BIDIR-6).
pub const DEFAULT_MAX_BUFFERED: u64 = 64 * 1024 * 1024;

/// What one call may take in (BIDIR-1: "every item that flows has a limit").
/// Beside the transport's per-connection call count, which counts a duplex
/// call as one call.
///
/// BIDIR-6, the owner's decision: nothing limits what has *passed through* a
/// call unless its method opts in (64 MiB is 56 minutes of 16 kHz PCM). What a
/// call costs is what it holds, so what is bounded is what it holds: `credit`
/// items, and past `max_buffered` bytes no more credit until the handler
/// drains below it. An obedient client is slowed, never ended (owner,
/// 2026-11-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallCeiling {
    /// Credit granted with the call's answer: items the caller may send
    /// before the callee grants more, and so the items it can hold. The
    /// callee's window, not a policy: it moves as the handler consumes.
    pub credit: u64,
    /// Input items over the call's life. `u64::MAX` (the default): no limit.
    pub max_items: u64,
    /// Input bytes over the call's life (each item as its JSON). `u64::MAX`
    /// (the default): no limit.
    pub max_bytes: u64,
    /// Input bytes held at once (received and not yet consumed) past which
    /// the callee grants no credit until it drains below them. Not a refusal:
    /// a client within its credit may still land up to a window's items.
    pub max_buffered: u64,
}

impl Default for CallCeiling {
    fn default() -> Self {
        Self { credit: DEFAULT_INPUT_WINDOW, max_items: u64::MAX, max_bytes: u64::MAX, max_buffered: DEFAULT_MAX_BUFFERED }
    }
}

/// BIDIR-8: which call a refusal was about — the connection it runs on and
/// its subscription there (the slot BIDIR-6 keys a duplex call by).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallRef {
    /// The connection, as the transport numbers it.
    pub conn: u64,
    /// The call's subscription on that connection.
    pub subscription: u64,
}

/// BIDIR-8: every typed refusal the gate makes over a duplex call — its
/// `error_kind` on the wire, and the `reason` of its audit record
/// ([`AuditRecordKind::DuplexRefused`](crate::audit::AuditRecordKind::DuplexRefused)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplexRefusalCode {
    /// The grant gate refused: at open, at a re-verify, or an answer by grant.
    Forbidden,
    /// No one proved, a sign-in ended (signed out, revoked) or expired.
    Unauthenticated,
    /// The connection's calls are all open (`too_many_calls {max}`).
    TooManyCalls,
    /// A frame or an answer from a connection that is not the call's.
    NotThisCall,
    /// An input item past the credit granted (`past_credit {seq, credit}`).
    PastCredit,
    /// Past the ceiling a method opted into (`too_much_input {limit, max}`,
    /// `limit` `items` or `bytes`).
    TooMuchInput,
    /// A question that needs a person's answer, answered by an agent.
    PersonRequired,
    /// A frame or an answer after the input half closed.
    InputClosed,
    /// A frame out of sequence on a socket, which delivers in order: a broken
    /// client (`out_of_sequence {seq, expected}`).
    OutOfSequence,
    /// An input item that does not decode as the method's type
    /// (`invalid_input {seq}`).
    InvalidInput,
}

impl DuplexRefusalCode {
    /// The `error_kind` it goes on the wire as.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::Unauthenticated => "unauthenticated",
            Self::TooManyCalls => "too_many_calls",
            Self::NotThisCall => "not_this_call",
            Self::PastCredit => "past_credit",
            Self::TooMuchInput => "too_much_input",
            Self::PersonRequired => "person_required",
            Self::InputClosed => "input_closed",
            Self::OutOfSequence => "out_of_sequence",
            Self::InvalidInput => "invalid_input",
        }
    }
}

/// The metadata key naming whom a hop acts for (IDENTITY-2's `for`;
/// RFC 8693's actor chain, read the other way): a list, nearest caller
/// first. It is attribution only — it grants nothing.
pub const FOR_KEY: &str = "for";

/// BIDIR-1 `forward` = identity: the context a call carries across a hop.
///
/// - the principal is the **hop** (`hop`: the calling service's own identity on
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

    /// BIDIR-6: nothing ends a call for what has passed through it unless
    /// its method opted in; what it holds is what is bounded.
    #[test]
    fn a_call_has_no_lifetime_ceiling_by_default() {
        let c = CallCeiling::default();
        assert_eq!((c.max_items, c.max_bytes), (u64::MAX, u64::MAX));
        assert_eq!((c.credit, c.max_buffered), (DEFAULT_INPUT_WINDOW, DEFAULT_MAX_BUFFERED));
    }

    #[test]
    fn answerer_reads_its_declaration() {
        assert_eq!(Answerer::parse("caller"), Ok(Answerer::Caller));
        assert_eq!(Answerer::parse(" person "), Ok(Answerer::Person));
        assert_eq!(Answerer::parse("grant:runs.approve"), Ok(Answerer::Grant("runs.approve".into())));
        assert!(Answerer::parse("grant:approve").is_err());
        assert!(Answerer::parse("anyone").is_err());
        assert_eq!(Answerer::default(), Answerer::Caller);
        // BIDIR-8: the schema's spelling round-trips; the default is absent.
        for a in [Answerer::Caller, Answerer::Person, Answerer::Grant("runs.approve".into())] {
            assert_eq!(Answerer::of_schema(a.declared().as_deref()), Ok(a.clone()));
        }
        assert_eq!(Answerer::Caller.declared(), None);
        assert!(Answerer::of_schema(Some("anyone")).unwrap_err().contains("`person`"));
    }
}
