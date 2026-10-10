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

/// A nostr key's adapter: verifies a NIP-98 event (kind 27235) that names
/// this service, and makes the key a `nostr:<hex>` principal named by its
/// npub.
///
/// At a WebSocket upgrade the event's `u` is the service's URL and its
/// `method` is GET (in any case: nostr-tools' examples write it
/// lowercase). Each event works once, within its window. IDENTITY-19:
/// [`Nip98Adapter::for_method`] takes another method, as a login endpoint
/// that is POSTed to does.
pub struct Nip98Adapter {
    urls: Vec<url::Url>,
    method: String,
    roles: HashMap<String, Vec<String>>,
    seen: Mutex<HashMap<String, u64>>,
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
        Ok(Self { urls, method: "GET".into(), roles: HashMap::new(), seen: Mutex::new(HashMap::new()) })
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
        use nostr::nips::nip19::ToBech32;

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
        let roles = self.roles.get(&hex).cloned().unwrap_or_default();
        Ok(Authenticated::new(principal, id, roles, Value::Object(meta)))
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
pub struct Carriers {
    chain: AuthenticatorChain,
    cookies: Vec<String>,
}

impl Carriers {
    /// The `access_token` and `nostr` cookies, then the bearer value.
    pub fn cookie_and_bearer(chain: AuthenticatorChain) -> Self {
        Self { chain, cookies: vec!["access_token".into(), "nostr".into()] }
    }

    /// Authenticate one value the transport offers, with the reason kept.
    pub async fn authenticate(&self, value: &str) -> Result<Authenticated, AuthnRejection> {
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
