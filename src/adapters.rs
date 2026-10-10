//! Provider adapters (IDENTITY-13): one per identity provider, each turning
//! that provider's credential into Plexus types at a service's boundary.
//!
//! # The rule these exist for
//!
//! A service never reasons about Auth0, plexus-idp or nostr. An adapter
//! verifies its provider's credential and produces an [`Authenticated`]:
//! a [`Principal`], a display name, roles and a tenant, all Plexus types.
//! Past the boundary the service sees only the [`AuthContext`] those become,
//! so swapping or adding a provider is configuration at the boundary and
//! nothing else.
//!
//! | provider | adapter | principal |
//! | --- | --- | --- |
//! | plexus-idp | [`OidcAdapter`], plexus-idp profile | `idp:<uuid>` |
//! | Auth0, Logto, any OIDC | [`OidcAdapter`], `auth0` or `generic` profile | `oidc:<provider>/<sub>` |
//! | WorkOS (AuthKit, SSO) | [`OidcAdapter`], `workos` profile | `oidc:workos/<user id>` |
//! | a nostr key | [`Nip98Adapter`] | `nostr:<hex>` |
//! | an agent's Ed25519 key | [`KeyProofAdapter`] | `key:<hex>` |
//!
//! [`Carriers`] puts a chain of adapters at a WebSocket upgrade: a
//! credential arrives in the `access_token` cookie, the `nostr` cookie, or
//! the `Authorization: Bearer` value, and reaches whichever adapter claims it.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine;
use serde_json::{Map, Value};

use crate::auth::{AuthContext, SessionValidator};
use crate::identity::{
    Authenticated, Authenticator, AuthenticatorChain, AuthnRejection, Issuer, Presentation,
    Principal,
};
use crate::oidc::{Audience, AudienceClaim, OidcConfig, OidcError, OidcValidator, VerifiedToken};
use crate::IssuerUrl;

// ── Names and errors ───────────────────────────────────────────────────

/// An adapter's provider name, as `oidc:<provider>/…` and the `provider`
/// metadata key say it: 1–32 of `a-z`, `0-9` and `-`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderName(String);

impl ProviderName {
    /// Validate a provider name.
    pub fn try_new(name: impl Into<String>) -> Result<Self, AdapterError> {
        let name = name.into();
        if crate::identity::valid_provider_name(&name) {
            Ok(Self(name))
        } else {
            Err(AdapterError::ProviderName(name))
        }
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why an adapter could not be configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// A provider name outside `[a-z0-9-]{1,32}`.
    ProviderName(String),
    /// An issuer that is not an `https://` URL (or `http://` on loopback).
    Issuer(String),
    /// An audience the OIDC config refuses.
    Audience(String),
    /// A service URL a NIP-98 adapter cannot parse.
    ServiceUrl(String),
    /// Two adapters in one chain speak for the same provider name
    /// (IDENTITY-27): both would mint the same principals.
    DuplicateProvider(String),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderName(n) => {
                write!(f, "provider name `{n}` must be 1-32 of a-z, 0-9 and -")
            }
            Self::Issuer(i) => write!(f, "issuer `{i}` is not an https URL (or http on loopback)"),
            Self::Audience(a) => write!(f, "audience `{a}` is not valid"),
            Self::ServiceUrl(u) => write!(f, "service URL `{u}` does not parse"),
            Self::DuplicateProvider(n) => {
                write!(f, "two adapters are named `{n}`: each provider needs its own name")
            }
        }
    }
}

impl std::error::Error for AdapterError {}

// ── OIDC ───────────────────────────────────────────────────────────────

/// WorkOS's API, the base of its per-client issuers.
pub const WORKOS_API: &str = "https://api.workos.com";

/// Where a provider's token puts the facts Plexus needs.
#[derive(Debug, Clone, Default)]
pub struct ClaimMap {
    /// Claims tried in order for the display name; the first string wins,
    /// then the `username` claim, then the subject.
    pub name: Vec<String>,
    /// The claim holding roles as an array of strings. `None` reads the
    /// `roles` claim.
    pub roles: Option<String>,
}

/// The namespace an [`OidcAdapter`] mints principals in.
#[derive(Debug, Clone)]
pub enum Namespace {
    /// plexus-idp: the subject is the user's UUID, so the principal is
    /// `idp:<uuid>`, the same one plexus-idp's own paths name.
    Idp,
    /// Any other provider: `oidc:<provider>/<sub>`.
    Oidc(ProviderName),
}

/// An OIDC provider's adapter: verifies its RS256 tokens from discovery and
/// JWKS (the [`OidcValidator`]) and maps its claims into Plexus types.
///
/// It claims only tokens whose `iss` is its issuer, read before
/// verification so that several providers can share one chain; once it
/// claims a token, any failure is a real rejection.
pub struct OidcAdapter {
    provider: ProviderName,
    namespace: Namespace,
    claims: ClaimMap,
    issuer: String,
    validator: OidcValidator,
}

impl OidcAdapter {
    /// An adapter over a configured validator. The profile constructors
    /// below are this, with each provider's namespace and claim map.
    pub fn with_validator(
        provider: ProviderName,
        namespace: Namespace,
        claims: ClaimMap,
        validator: OidcValidator,
    ) -> Self {
        let issuer = validator
            .config()
            .issuer()
            .as_url()
            .as_str()
            .trim_end_matches('/')
            .to_string();
        Self { provider, namespace, claims, issuer, validator }
    }

    /// The plexus-idp profile over a validator: principal `idp:<uuid>`,
    /// roles from `roles`, name from `username`.
    pub fn plexus_idp_with(validator: OidcValidator) -> Self {
        Self::with_validator(
            ProviderName("plexus-idp".into()),
            Namespace::Idp,
            ClaimMap::default(),
            validator,
        )
    }

    /// The Auth0 profile over a validator: principal `oidc:auth0/<sub>`,
    /// name from `nickname`, `name` or `email`, and roles from
    /// `roles_claim`, the namespaced custom claim an Auth0 Action adds
    /// (Auth0 requires custom claims to be URL-named).
    pub fn auth0_with(validator: OidcValidator, roles_claim: Option<&str>) -> Self {
        Self::with_validator(
            ProviderName("auth0".into()),
            Namespace::Oidc(ProviderName("auth0".into())),
            ClaimMap {
                name: vec!["nickname".into(), "name".into(), "email".into()],
                roles: roles_claim.map(str::to_string),
            },
            validator,
        )
    }

    /// The WorkOS profile over a validator (IDENTITY-30): principal
    /// `oidc:workos/<user id>`, roles from `roles` (the organization
    /// membership's). WorkOS's access token names nobody, so the name is the
    /// user id unless a later token carries `email`; a login flow names the
    /// person from the authenticate response instead.
    pub fn workos_with(validator: OidcValidator) -> Self {
        Self::with_validator(
            ProviderName("workos".into()),
            Namespace::Oidc(ProviderName("workos".into())),
            ClaimMap { name: vec!["email".into()], roles: None },
            validator,
        )
    }

    /// The validator configuration for one WorkOS environment's client: the
    /// issuer is `<base>/user_management/<client_id>` (base
    /// `https://api.workos.com` unless given), which publishes discovery;
    /// its access tokens carry no `aud`, so the audience is the client id,
    /// read from `client_id`. A token for another client of the same
    /// account fails both checks.
    pub fn workos_config(client_id: &str, base: Option<&str>) -> Result<OidcConfig, AdapterError> {
        let base = base.unwrap_or(WORKOS_API).trim_end_matches('/');
        let issuer = format!("{base}/user_management/{client_id}");
        Ok(Self::config(&issuer, client_id)?.with_audience_claim(AudienceClaim::ClientId))
    }

    /// The validator configuration for `issuer` and `audience`.
    pub fn config(issuer: &str, audience: &str) -> Result<OidcConfig, AdapterError> {
        let url = issuer.parse().map_err(|_| AdapterError::Issuer(issuer.to_string()))?;
        let issuer_url = IssuerUrl::try_new(url).map_err(|_| AdapterError::Issuer(issuer.to_string()))?;
        let audience = Audience::try_new(audience).map_err(|_| AdapterError::Audience(audience.to_string()))?;
        Ok(OidcConfig::new(issuer_url, audience))
    }

    /// plexus-idp at `issuer`, for tokens minted for `audience`.
    #[cfg(feature = "oidc-reqwest")]
    pub fn plexus_idp(issuer: &str, audience: &str) -> Result<Self, AdapterError> {
        Ok(Self::plexus_idp_with(OidcValidator::new(Self::config(issuer, audience)?)))
    }

    /// An Auth0 tenant at `domain` (`https://acme.auth0.com/`), for tokens
    /// minted for `audience` (the API identifier).
    #[cfg(feature = "oidc-reqwest")]
    pub fn auth0(domain: &str, audience: &str, roles_claim: Option<&str>) -> Result<Self, AdapterError> {
        Ok(Self::auth0_with(OidcValidator::new(Self::config(domain, audience)?), roles_claim))
    }

    /// A WorkOS environment's client (`client_01…`), at `base` when it is
    /// not `https://api.workos.com`.
    #[cfg(feature = "oidc-reqwest")]
    pub fn workos(client_id: &str, base: Option<&str>) -> Result<Self, AdapterError> {
        Ok(Self::workos_with(OidcValidator::new(Self::workos_config(client_id, base)?)))
    }

    /// Any other OIDC provider, named `provider`, with its own claim map.
    #[cfg(feature = "oidc-reqwest")]
    pub fn generic(
        provider: &str,
        issuer: &str,
        audience: &str,
        claims: ClaimMap,
    ) -> Result<Self, AdapterError> {
        let name = ProviderName::try_new(provider)?;
        Ok(Self::with_validator(
            name.clone(),
            Namespace::Oidc(name),
            claims,
            OidcValidator::new(Self::config(issuer, audience)?),
        ))
    }

    /// The provider this adapter speaks for.
    pub fn provider(&self) -> &ProviderName {
        &self.provider
    }

    fn identity(&self, token: &VerifiedToken) -> Result<Authenticated, AuthnRejection> {
        let sub = token.user().user_id();
        let principal = match &self.namespace {
            Namespace::Idp => Principal::new(Issuer::Idp, sub),
            Namespace::Oidc(provider) => Principal::oidc(provider.as_str(), sub),
        }
        .map_err(|e| AuthnRejection::Malformed(e.to_string()))?;

        let roles = match &self.claims.roles {
            Some(claim) => strings(token.claim(claim)),
            None => token.roles().to_vec(),
        };
        let name = self
            .claims
            .name
            .iter()
            .find_map(|c| token.claim(c).and_then(Value::as_str))
            .or_else(|| token.username())
            .unwrap_or(sub)
            .to_string();

        let mut meta = Map::new();
        meta.insert("name".into(), Value::String(name.clone()));
        meta.insert("username".into(), Value::String(name));
        meta.insert("provider".into(), Value::String(self.provider.to_string()));
        meta.insert("auth_method".into(), Value::String("oidc".into()));
        // IDENTITY-19: when the credential ends, so a service can stop
        // honouring an identity its token no longer vouches for.
        meta.insert("expires_at".into(), Value::from(token.user().expires_at()));
        if let Some(t) = token.tenant_id() {
            meta.insert("org_id".into(), Value::String(t.as_str().to_string()));
            meta.insert("tenant_id".into(), Value::String(t.as_str().to_string()));
        }
        Ok(Authenticated::new(principal, token.session_id(), roles, Value::Object(meta)))
    }
}

/// A claim's array of strings; anything else is no roles.
fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

/// The `iss` a JWT claims, read without verifying it: only for choosing
/// which adapter verifies the token.
fn unverified_issuer(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    Some(claims.get("iss")?.as_str()?.trim_end_matches('/').to_string())
}

fn rejection(e: OidcError) -> AuthnRejection {
    match e {
        OidcError::Expired => AuthnRejection::Expired,
        OidcError::InvalidSignature => AuthnRejection::SignatureInvalid,
        OidcError::Discovery(_) | OidcError::JwksUnavailable(_) => AuthnRejection::Backend(e.to_string()),
        other => AuthnRejection::Malformed(other.to_string()),
    }
}

#[async_trait]
impl Authenticator for OidcAdapter {
    fn name(&self) -> &str {
        self.provider.as_str()
    }

    fn accepts(&self, presentation: &Presentation) -> bool {
        match presentation {
            Presentation::Bearer { token } => unverified_issuer(token).as_deref() == Some(self.issuer.as_str()),
            _ => false,
        }
    }

    async fn authenticate(&self, presentation: &Presentation) -> Result<Authenticated, AuthnRejection> {
        if !self.accepts(presentation) {
            return Err(AuthnRejection::unsupported(self.name(), presentation));
        }
        let Presentation::Bearer { token } = presentation else {
            return Err(AuthnRejection::unsupported(self.name(), presentation));
        };
        let verified = self.validator.validate_token(token).await.map_err(rejection)?;
        self.identity(&verified)
    }
}

// ── nostr (NIP-98) ─────────────────────────────────────────────────────

/// How old a NIP-98 event may be, and how far ahead of this clock: the
/// window rust-nostr's own NIP-98 check uses.
const WINDOW_PAST_SECS: u64 = 60;
const WINDOW_FUTURE_SECS: u64 = 30;

/// How long an identity a NIP-98 event proved is honoured (IDENTITY-27):
/// twelve hours from verification, unless [`Nip98Adapter::with_lifetime`]
/// says otherwise. The event itself is good for a minute, but a WebSocket
/// it opened would otherwise stand for as long as the socket does; a
/// working day bounds that, and a client signs a fresh event to reconnect.
pub const NIP98_DEFAULT_LIFETIME_SECS: u64 = 12 * 60 * 60;

/// A nostr key's adapter: verifies a NIP-98 event (kind 27235) that names
/// this service, and makes the key a `nostr:<hex>` principal named by its
/// npub.
///
/// At a WebSocket upgrade the event's `u` is the service's URL and its
/// `method` is GET (in any case: nostr-tools' examples write it
/// lowercase). Each event works once, within its window. IDENTITY-19:
/// [`Nip98Adapter::for_method`] takes another method, as a login endpoint
/// that is POSTed to does.
///
/// IDENTITY-27:
///
/// - The identity carries `expires_at` (seconds since the epoch): the
///   verification time plus the adapter's lifetime
///   ([`NIP98_DEFAULT_LIFETIME_SECS`], or [`Nip98Adapter::with_lifetime`]).
/// - A request body is bound by NIP-98's `payload` tag (the SHA-256 of the
///   body, hex) only through [`Nip98Adapter::authenticate_request`], which
///   is given the body. [`Authenticator::authenticate`] sees a
///   [`Presentation`], which carries no body, so it does not check a
///   `payload` tag: at a WebSocket upgrade (a GET) there is no body, and an
///   endpoint whose body matters calls `authenticate_request`.
/// - The replay ledger is this adapter's memory, so an event is refused a
///   second time only by the same process. Two processes behind one URL
///   would each accept it once; a deployment like that needs a shared
///   ledger.
pub struct Nip98Adapter {
    urls: Vec<url::Url>,
    method: String,
    roles: HashMap<String, Vec<String>>,
    seen: Mutex<HashMap<String, u64>>,
    lifetime_secs: u64,
}

impl Nip98Adapter {
    /// An adapter accepting events whose `u` is one of `urls`.
    pub fn new<I, S>(urls: I) -> Result<Self, AdapterError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let urls = urls
            .into_iter()
            .map(|u| url::Url::parse(u.as_ref()).map_err(|_| AdapterError::ServiceUrl(u.as_ref().to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            urls,
            method: "GET".into(),
            roles: HashMap::new(),
            seen: Mutex::new(HashMap::new()),
            lifetime_secs: NIP98_DEFAULT_LIFETIME_SECS,
        })
    }

    /// Honour an identity this adapter proves for `secs` after it is
    /// verified (its `expires_at`), instead of
    /// [`NIP98_DEFAULT_LIFETIME_SECS`].
    pub fn with_lifetime(mut self, secs: u64) -> Self {
        self.lifetime_secs = secs;
        self
    }

    /// Authenticate a request whose body is known: as
    /// [`Authenticator::authenticate`], and the event's `payload` tag must
    /// be the SHA-256 (hex) of `body`. A non-empty body requires the tag; an
    /// empty body admits an event without one, and one whose tag hashes
    /// the empty body.
    pub async fn authenticate_request(&self, token: &str, body: &[u8]) -> Result<Authenticated, AuthnRejection> {
        self.verify(&Presentation::Bearer { token: token.to_string() }, Some(body))
    }

    /// Events must name `method` (in any case) instead of GET.
    pub fn for_method(mut self, method: &str) -> Self {
        self.method = method.to_ascii_uppercase();
        self
    }

    /// Give the key `pubkey_hex` these roles. Keys not named here have none.
    pub fn with_roles(mut self, pubkey_hex: &str, roles: Vec<String>) -> Self {
        self.roles.insert(pubkey_hex.to_ascii_lowercase(), roles);
        self
    }
}

/// The NIP-98 event a value carries: base64 (standard or URL-safe), with or
/// without the `Nostr ` scheme, decoding to a kind-27235 event.
fn nip98_event(value: &str) -> Option<nostr::event::Event> {
    let encoded = value.trim();
    let encoded = encoded.strip_prefix("Nostr ").unwrap_or(encoded);
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    let json = engines.iter().find_map(|e| e.decode(encoded).ok())?;
    let event = nostr::event::Event::from_json(&json).ok()?;
    (event.kind == nostr::event::Kind::HttpAuth).then_some(event)
}

#[async_trait]
impl Authenticator for Nip98Adapter {
    fn name(&self) -> &str {
        "nostr"
    }

    fn accepts(&self, presentation: &Presentation) -> bool {
        matches!(presentation, Presentation::Bearer { token } if nip98_event(token).is_some())
    }

    async fn authenticate(&self, presentation: &Presentation) -> Result<Authenticated, AuthnRejection> {
        self.verify(presentation, None)
    }
}

impl Nip98Adapter {
    /// The checks, with the request body when the caller has it.
    fn verify(&self, presentation: &Presentation, body: Option<&[u8]>) -> Result<Authenticated, AuthnRejection> {
        use nostr::nips::nip19::ToBech32;
        use sha2::Digest;

        let event = match presentation {
            Presentation::Bearer { token } => nip98_event(token),
            _ => None,
        }
        .ok_or_else(|| AuthnRejection::unsupported(self.name(), presentation))?;

        let tag = |name: &str| {
            event.tags.iter().find_map(|t| match t.as_slice() {
                [n, v, ..] if n == name => Some(v.clone()),
                _ => None,
            })
        };
        let u = tag("u").and_then(|u| url::Url::parse(&u).ok());
        if !u.as_ref().is_some_and(|u| self.urls.contains(u)) {
            return Err(AuthnRejection::Malformed("NIP-98: `u` is not this service".into()));
        }
        if !tag("method").is_some_and(|m| m.eq_ignore_ascii_case(&self.method)) {
            return Err(AuthnRejection::Malformed(format!("NIP-98: `method` is not {}", self.method)));
        }
        let now = nostr::types::Timestamp::now().as_secs();
        let at = event.created_at.as_secs();
        if at + WINDOW_PAST_SECS < now || at > now + WINDOW_FUTURE_SECS {
            return Err(AuthnRejection::Expired);
        }
        event.verify().map_err(|_| AuthnRejection::SignatureInvalid)?;
        if let Some(body) = body {
            let want: String = sha2::Sha256::digest(body).iter().map(|b| format!("{b:02x}")).collect();
            match tag("payload") {
                Some(p) if p.eq_ignore_ascii_case(&want) => {}
                Some(_) => return Err(AuthnRejection::Malformed("NIP-98: `payload` is not this body's hash".into())),
                None if body.is_empty() => {}
                None => return Err(AuthnRejection::Malformed("NIP-98: a body needs a `payload` tag".into())),
            }
        }

        let id = event.id.to_hex();
        {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| AuthnRejection::Backend("NIP-98 replay ledger unavailable".into()))?;
            seen.retain(|_, until| *until > now);
            if seen
                .insert(id.clone(), now + WINDOW_PAST_SECS + WINDOW_FUTURE_SECS + 30)
                .is_some()
            {
                return Err(AuthnRejection::Malformed("NIP-98: this event was already used".into()));
            }
        }

        let hex = event.pubkey.to_hex();
        let principal = Principal::new(Issuer::Nostr, hex.clone())
            .map_err(|e| AuthnRejection::Malformed(e.to_string()))?;
        let name = event.pubkey.to_bech32().unwrap_or_else(|_| hex.clone());
        let mut meta = Map::new();
        meta.insert("name".into(), Value::String(name.clone()));
        meta.insert("username".into(), Value::String(name));
        meta.insert("provider".into(), Value::String("nostr".into()));
        meta.insert("auth_method".into(), Value::String("nip98".into()));
        meta.insert("expires_at".into(), Value::from(now.saturating_add(self.lifetime_secs)));
        let roles = self.roles.get(&hex).cloned().unwrap_or_default();
        Ok(Authenticated::new(principal, id, roles, Value::Object(meta)))
    }
}

// ── Agent keys (IDENTITY-41) ───────────────────────────────────────────

/// What a key proof starts with, as a bearer value.
pub const KEY_PROOF_PREFIX: &str = "plexus-key.";

/// The first line of the message a key proof signs.
pub const KEY_PROOF_CONTEXT: &str = "plexus-key-login/v1";

/// How long the identity a key proof opens stands, from its `ts`: a proof
/// opens a connection, it is not a session.
pub const KEY_PROOF_LIFETIME_SECS: i64 = 300;

/// How old a key proof's `ts` may be, and how far ahead of this clock.
const KEY_WINDOW_PAST_SECS: i64 = 60;
const KEY_WINDOW_FUTURE_SECS: i64 = 30;

/// A key proof's JSON, field for field as the wire says it, in its order.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct KeyProofJson {
    v: u64,
    key: String,
    aud: String,
    agent: String,
    nonce: String,
    ts: i64,
    sig: String,
}

/// The exact bytes a key proof signs: `plexus-key-login/v1\n<aud>\n<agent>\n<nonce>\n<ts>`,
/// no trailing newline. `nonce` is the base64url (no padding) string the
/// proof carries.
pub fn key_proof_message(aud: &str, agent: &str, nonce: &str, ts: i64) -> String {
    format!("{KEY_PROOF_CONTEXT}\n{aud}\n{agent}\n{nonce}\n{ts}")
}

/// Whether `agent` is an agent id: 1–64 of `[A-Za-z0-9._-]`.
pub fn valid_agent_id(agent: &str) -> bool {
    (1..=64).contains(&agent.len())
        && agent.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The principal an Ed25519 public key is: `key:<64 lowercase hex>`.
pub fn key_principal(public_key: &[u8; 32]) -> Principal {
    Principal::new(Issuer::Key, hex(public_key)).expect("32 bytes are 64 lowercase hex")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Sign a key proof, as an agent does: the bearer value
/// `plexus-key.<base64url(JSON)>` for the key whose 32-byte Ed25519 seed is
/// `seed`, naming the socket `aud` it is for, the agent id, a 32-byte
/// `nonce` and `ts` (unix seconds). The reference for every client: the
/// JSON's fields are in the wire's order, `{"v":1,"key":…,"aud":…,
/// "agent":…,"nonce":…,"ts":…,"sig":…}`.
pub fn sign_key_proof(seed: &[u8; 32], aud: &str, agent: &str, nonce: &[u8; 32], ts: i64) -> String {
    use ed25519_dalek::Signer;
    let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    let nonce = b64.encode(nonce);
    let sig = signing.sign(key_proof_message(aud, agent, &nonce, ts).as_bytes());
    let proof = KeyProofJson {
        v: 1,
        key: hex(signing.verifying_key().as_bytes()),
        aud: aud.to_string(),
        agent: agent.to_string(),
        nonce,
        ts,
        sig: b64.encode(sig.to_bytes()),
    };
    let json = serde_json::to_vec(&proof).expect("a key proof serializes");
    format!("{KEY_PROOF_PREFIX}{}", b64.encode(json))
}

/// The proof a bearer value carries, decoded but not checked: `None` when it
/// is not `plexus-key.<base64url-nopad JSON>` of the proof's shape.
fn key_proof(value: &str) -> Option<KeyProofJson> {
    let encoded = value.trim().strip_prefix(KEY_PROOF_PREFIX)?;
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&json).ok()
}

/// The parts of a proof as a [`Presentation::SignedChallenge`] carries them:
/// `scheme` `ed25519`, `key_id` the key's hex, `challenge` the signed
/// message itself, `signature` base64url.
fn signed_challenge(key_id: &str, challenge: &str, signature: &str) -> Option<KeyProofJson> {
    let mut lines = challenge.split('\n');
    if lines.next()? != KEY_PROOF_CONTEXT {
        return None;
    }
    let (aud, agent, nonce, ts) = (lines.next()?, lines.next()?, lines.next()?, lines.next()?);
    if lines.next().is_some() {
        return None;
    }
    let ts: i64 = ts.parse().ok()?;
    // The message must be exactly the canonical one for these parts.
    if ts.to_string() != challenge.rsplit('\n').next()? {
        return None;
    }
    Some(KeyProofJson {
        v: 1,
        key: key_id.to_string(),
        aud: aud.to_string(),
        agent: agent.to_string(),
        nonce: nonce.to_string(),
        ts,
        sig: signature.to_string(),
    })
}

/// A replay ledger's key: the public key and the nonce, as bytes.
type KeyAndNonce = ([u8; 32], [u8; 32]);

/// An agent's key's adapter (IDENTITY-40's wire): verifies a fresh Ed25519
/// proof naming one of this server's socket URLs and an agent id, and makes
/// the key a `key:<hex>` principal named by the agent.
///
/// A proof is the bearer value `plexus-key.<base64url-nopad of JSON>`,
/// `{"v":1,"key":"<64 hex>","aud":"<ws url>","agent":"<id>","nonce":"<base64url, 32 bytes>","ts":<unix s>,"sig":"<base64url, 64 bytes>"}`,
/// where `sig` is Ed25519 over [`key_proof_message`]. It is accepted when
/// `v` is 1, `agent` is 1–64 of `[A-Za-z0-9._-]`, the nonce is 32 bytes,
/// `ts` is within −60 s / +30 s of now, `aud` is one of the adapter's
/// audiences (a trailing `/` aside), the signature verifies (strictly), and
/// the `(key, nonce)` pair has not been accepted before. The identity:
/// principal `key:<hex>`, metadata `agent` and `name` the agent id,
/// `provider` and `auth_method` `key`, `expires_at` `ts + 300`.
///
/// It also takes a [`Presentation::SignedChallenge`] of scheme `ed25519`
/// whose `challenge` is the signed message itself.
///
/// The replay ledger is this adapter's memory, pruned as proofs age out of
/// the window: one process refuses a proof twice; two processes behind one
/// URL would each accept it once.
pub struct KeyProofAdapter {
    audiences: Vec<String>,
    seen: Mutex<HashMap<KeyAndNonce, i64>>,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl fmt::Debug for KeyProofAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyProofAdapter").field("audiences", &self.audiences).finish()
    }
}

fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn audience_form(aud: &str) -> &str {
    aud.trim_end_matches('/')
}

impl KeyProofAdapter {
    /// An adapter accepting proofs whose `aud` is one of `audiences`: the
    /// WebSocket URLs this server is dialed at (`ws://127.0.0.1:<port>`,
    /// `ws://localhost:<port>`, any public one).
    pub fn new<I, S>(audiences: I) -> Result<Self, AdapterError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Vec::new();
        for a in audiences {
            let a = a.as_ref().trim();
            match url::Url::parse(a) {
                Ok(u) if matches!(u.scheme(), "ws" | "wss") => {}
                _ => return Err(AdapterError::ServiceUrl(a.to_string())),
            }
            let a = audience_form(a).to_string();
            if !out.contains(&a) {
                out.push(a);
            }
        }
        Ok(Self { audiences: out, seen: Mutex::new(HashMap::new()), clock: Box::new(system_now) })
    }

    /// Read the time (unix seconds) from `clock` instead of the system's —
    /// for tests and fixed vectors.
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// The audiences it accepts.
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    fn proof_of(presentation: &Presentation) -> Option<KeyProofJson> {
        match presentation {
            Presentation::Bearer { token } => key_proof(token),
            Presentation::SignedChallenge { scheme, key_id, challenge, signature } if scheme == "ed25519" => {
                signed_challenge(key_id, challenge, signature)
            }
            _ => None,
        }
    }

    fn verify(&self, proof: KeyProofJson) -> Result<Authenticated, AuthnRejection> {
        use ed25519_dalek::{Signature, VerifyingKey};
        let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let bad = |why: &str| AuthnRejection::Malformed(format!("key proof: {why}"));

        if proof.v != 1 {
            return Err(bad("`v` is not 1"));
        }
        let principal = Principal::new(Issuer::Key, proof.key.clone()).map_err(|e| bad(&e.to_string()))?;
        let key_bytes = unhex_32(&proof.key).ok_or_else(|| bad("`key` is not 32 bytes of hex"))?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| bad("`key` is not an Ed25519 public key"))?;
        if !valid_agent_id(&proof.agent) {
            return Err(bad("`agent` must be 1-64 of A-Z, a-z, 0-9, `.`, `_` and `-`"));
        }
        let nonce: [u8; 32] = b64
            .decode(&proof.nonce)
            .ok()
            .and_then(|n| n.try_into().ok())
            .ok_or_else(|| bad("`nonce` is not 32 bytes of base64url"))?;
        if !self.audiences.iter().any(|a| a == audience_form(&proof.aud)) {
            return Err(bad("`aud` is not this server"));
        }
        let now = (self.clock)();
        if proof.ts + KEY_WINDOW_PAST_SECS < now || proof.ts > now + KEY_WINDOW_FUTURE_SECS {
            return Err(AuthnRejection::Expired);
        }
        let sig: [u8; 64] = b64
            .decode(&proof.sig)
            .ok()
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| bad("`sig` is not 64 bytes of base64url"))?;
        let message = key_proof_message(&proof.aud, &proof.agent, &proof.nonce, proof.ts);
        key.verify_strict(message.as_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| AuthnRejection::SignatureInvalid)?;

        {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| AuthnRejection::Backend("key proof replay ledger unavailable".into()))?;
            // A proof past the window is refused anyway: forget it then.
            seen.retain(|_, until| *until >= now);
            if seen.insert((key_bytes, nonce), proof.ts + KEY_WINDOW_PAST_SECS).is_some() {
                return Err(bad("this proof was already used"));
            }
        }

        let mut meta = Map::new();
        meta.insert("agent".into(), Value::String(proof.agent.clone()));
        meta.insert("name".into(), Value::String(proof.agent));
        meta.insert("provider".into(), Value::String("key".into()));
        meta.insert("auth_method".into(), Value::String("key".into()));
        meta.insert("expires_at".into(), Value::from(proof.ts + KEY_PROOF_LIFETIME_SECS));
        Ok(Authenticated::new(principal, proof.nonce, Vec::new(), Value::Object(meta)))
    }
}

#[async_trait]
impl Authenticator for KeyProofAdapter {
    fn name(&self) -> &str {
        "key"
    }

    fn accepts(&self, presentation: &Presentation) -> bool {
        match presentation {
            Presentation::Bearer { token } => token.trim().starts_with(KEY_PROOF_PREFIX),
            Presentation::SignedChallenge { scheme, .. } => scheme == "ed25519",
            _ => false,
        }
    }

    async fn authenticate(&self, presentation: &Presentation) -> Result<Authenticated, AuthnRejection> {
        if !self.accepts(presentation) {
            return Err(AuthnRejection::unsupported(self.name(), presentation));
        }
        let proof = Self::proof_of(presentation)
            .ok_or_else(|| AuthnRejection::Malformed("key proof: not plexus-key.<base64url JSON> of a proof".into()))?;
        self.verify(proof)
    }
}

// ── Carriers ───────────────────────────────────────────────────────────

/// Where credentials ride into a WebSocket upgrade, and the
/// [`SessionValidator`] a service installs there.
///
/// The transport offers the `Cookie` header, then the `Authorization:
/// Bearer` value. A cookie header is searched for the carried cookies in
/// order (`access_token` for a token, `nostr` for a NIP-98 event; a browser
/// can only send cookies); any other value is presented as a bearer token.
/// Whichever adapter in the chain claims the credential decides.
///
/// [`Carriers::bearer_only`] reads no cookies (IDENTITY-27): a cookie is
/// scoped to a host, not a port, so any page served from another port of
/// the same host can plant one; only the `Authorization` value is then a
/// credential, and a `Cookie` header the transport offers is refused
/// without reaching the chain.
pub struct Carriers {
    chain: AuthenticatorChain,
    cookies: Vec<String>,
}

impl Carriers {
    /// The `access_token` and `nostr` cookies, then the bearer value.
    pub fn cookie_and_bearer(chain: AuthenticatorChain) -> Self {
        Self { chain, cookies: vec!["access_token".into(), "nostr".into()] }
    }

    /// Only the `Authorization: Bearer` value (IDENTITY-27): no cookie is a
    /// credential, and a value shaped like a `Cookie` header is refused
    /// before any adapter sees it.
    pub fn bearer_only(chain: AuthenticatorChain) -> Self {
        Self { chain, cookies: Vec::new() }
    }

    /// As [`Carriers::cookie_and_bearer`], refusing a chain in which two
    /// adapters share a provider name (IDENTITY-27).
    pub fn try_cookie_and_bearer(chain: AuthenticatorChain) -> Result<Self, AdapterError> {
        unique_names(&chain)?;
        Ok(Self::cookie_and_bearer(chain))
    }

    /// As [`Carriers::bearer_only`], refusing a chain in which two adapters
    /// share a provider name (IDENTITY-27).
    pub fn try_bearer_only(chain: AuthenticatorChain) -> Result<Self, AdapterError> {
        unique_names(&chain)?;
        Ok(Self::bearer_only(chain))
    }

    /// Authenticate one value the transport offers, with the reason kept.
    pub async fn authenticate(&self, value: &str) -> Result<Authenticated, AuthnRejection> {
        if self.cookies.is_empty() && looks_like_cookie_header(value) {
            return Err(AuthnRejection::Malformed(
                "a Cookie header is not a credential here (bearer only)".into(),
            ));
        }
        let mut last = None;
        for name in &self.cookies {
            if let Some(token) = cookie(value, name) {
                match self.chain.authenticate(&Presentation::Bearer { token: token.to_string() }).await {
                    Ok(ok) => return Ok(ok),
                    Err(e) => last = Some(e),
                }
            }
        }
        if let Some(e) = last {
            return Err(e);
        }
        self.chain.authenticate(&Presentation::Bearer { token: value.trim().to_string() }).await
    }
}

/// Every name in `chain` once.
fn unique_names(chain: &AuthenticatorChain) -> Result<(), AdapterError> {
    let mut names = std::collections::HashSet::new();
    for name in chain.names() {
        if !names.insert(name) {
            return Err(AdapterError::DuplicateProvider(name.to_string()));
        }
    }
    Ok(())
}

/// Whether a value is a `Cookie` header (`name=value`, `;`-separated)
/// rather than a bearer credential. A JWT holds no `=` or `;`; a base64
/// NIP-98 event holds `=` only as trailing padding.
fn looks_like_cookie_header(value: &str) -> bool {
    let v = value.trim();
    v.contains(';') || v.trim_end_matches('=').contains('=')
}

/// A named cookie's value in a `Cookie` header.
fn cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (n, v) = pair.trim().split_once('=')?;
        (n == name && !v.is_empty()).then_some(v.trim())
    })
}

#[async_trait]
impl SessionValidator for Carriers {
    async fn validate(&self, value: &str) -> Option<AuthContext> {
        match self.authenticate(value).await {
            Ok(ok) => Some(ok.into_auth_context()),
            Err(e) => {
                tracing::debug!(target: "plexus::auth", error = %e, "no adapter admitted the caller");
                None
            }
        }
    }
}
