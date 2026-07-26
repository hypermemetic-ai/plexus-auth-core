//! The [`Authenticator`] seam: credential material in, verified
//! [`Principal`] out.
//!
//! # Why a trait
//!
//! Before this module, "is this caller who they say they are" was answered by
//! whatever [`SessionValidator`](crate::SessionValidator) a backend happened
//! to install, and each validator hard-wired its own credential handling —
//! plexus-idp's, for example, parsed a cookie, tried an RS256 JWT, then fell
//! back to an API-key lookup, all inside one `validate` method. There was no
//! place to *add* a credential kind, only a place to edit one.
//!
//! An `Authenticator` is one credential kind's verifier. A backend composes
//! several into an [`AuthenticatorChain`], which is itself a
//! `SessionValidator` — so the new seam plugs into the existing perimeter
//! without any transport change.
//!
//! # The shape that keeps NIP-42 out of the trait
//!
//! Three facts make a self-sovereign, challenge-response credential
//! expressible without touching [`Authenticator`]:
//!
//! 1. [`Presentation`] carries a
//!    [`SignedChallenge`](Presentation::SignedChallenge) variant. A NIP-42
//!    authenticator reads `scheme == "nip42"`, `key_id` (the hex pubkey),
//!    `challenge` (the relay-issued nonce), and `signature` — no new variant
//!    needed, and `#[non_exhaustive]` means adding one later is not breaking
//!    anyway.
//! 2. [`Principal`] already namespaces `nostr:<64-hex>`, so the *output* type
//!    needs no widening.
//! 3. [`Authenticator::accepts`] lets each impl claim only its own material,
//!    so a chain can hold verifiers with completely unrelated proof models.
//!
//! # What is proof and what is data
//!
//! A [`Principal`] is a *name* — anyone can parse one out of a string.
//! [`Authenticated`] is the *proof*: its only constructor is
//! [`Authenticated::new`], and by convention the sole callers are
//! `Authenticator` impls that have verified the material they were handed.
//! Downstream code should take `Authenticated`, not `Principal`, when it
//! wants to know that a check happened.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value};

use super::linking::{CredentialClass, CredentialLink};
use super::principal::{Issuer, Principal};
use crate::auth::{AuthContext, SessionValidator, PRINCIPAL_CLAIM};

/// Credential material as a transport presented it.
///
/// The variants describe *carriers and proof shapes*, not products: `Bearer`
/// is "an opaque token in the `Authorization` header", not "a JWT". Which
/// [`Authenticator`] handles a given presentation is decided by
/// [`Authenticator::accepts`], never by the variant alone — an API key and a
/// JWT both arrive as `Bearer` in practice, and both authenticators get a
/// look.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Presentation {
    /// A bearer token, as extracted from `Authorization: Bearer <token>`.
    Bearer {
        /// The raw token, already stripped of the `Bearer ` prefix.
        token: String,
    },

    /// An API key presented in a dedicated header or query parameter.
    ApiKey {
        /// The raw key, exactly as presented (never the digest — the
        /// authenticator owns the digest function).
        key: String,
    },

    /// A raw `Cookie:` header value, with all its pairs intact.
    Cookie {
        /// The unparsed header value, e.g. `"a=1; access_token=eyJ…"`.
        header: String,
    },

    /// A signed challenge-response: the caller proved possession of a key by
    /// signing a server-issued nonce.
    ///
    /// This is the variant that makes NIP-42, WebAuthn, and mTLS-style proofs
    /// expressible without changing [`Authenticator`]. The fields are
    /// deliberately scheme-agnostic strings; the authenticator that claims a
    /// `scheme` owns their interpretation.
    SignedChallenge {
        /// Names the proof scheme, e.g. `"nip42"`. An authenticator matches
        /// on this in [`Authenticator::accepts`].
        scheme: String,
        /// The public identifier of the signing key (for nostr, the 64-hex
        /// x-only pubkey — which is also the `nostr:` principal subject).
        key_id: String,
        /// The server-issued nonce that was signed.
        challenge: String,
        /// The signature over `challenge`, in the scheme's own encoding.
        signature: String,
    },
}

impl Presentation {
    /// A short, non-secret label for logs and audit records.
    ///
    /// Never includes the material itself — a `Debug` of a `Presentation`
    /// does, so prefer this in anything that is written down.
    pub fn kind_label(&self) -> &str {
        match self {
            Self::Bearer { .. } => "bearer",
            Self::ApiKey { .. } => "apikey",
            Self::Cookie { .. } => "cookie",
            Self::SignedChallenge { scheme, .. } => scheme,
        }
    }
}

/// Why an [`Authenticator`] refused to vouch for a [`Presentation`].
///
/// The distinction that matters most for a chain is
/// [`Unsupported`](AuthnRejection::Unsupported) versus everything else:
/// `Unsupported` means "not my credential kind, ask the next one", while every
/// other variant means "this *was* mine and it failed". A chain that treated
/// them alike would let a revoked API key fall through to a validator that
/// happened to accept it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthnRejection {
    /// This authenticator does not handle this credential kind. Advisory —
    /// a chain moves on.
    Unsupported {
        /// The authenticator that declined.
        authenticator: String,
        /// The presentation's [`kind_label`](Presentation::kind_label).
        presented: String,
    },

    /// The material was structurally wrong: unparseable token, missing
    /// cookie, subject that does not fit the issuer's grammar.
    Malformed(String),

    /// The material was well-formed and genuine but past its validity window.
    Expired,

    /// A signature or MAC did not verify. Distinct from `Malformed` so audit
    /// can separate "garbage" from "forgery attempt".
    SignatureInvalid,

    /// Well-formed material naming something the store has never seen.
    UnknownCredential,

    /// Known material that has been explicitly withdrawn.
    Revoked,

    /// The authenticator could not reach the store, key set, or issuer it
    /// needed. **Not** an authentication failure — callers should surface
    /// this as a 5xx, not a 401.
    Backend(String),
}

impl std::fmt::Display for AuthnRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported {
                authenticator,
                presented,
            } => write!(
                f,
                "authenticator `{authenticator}` does not handle `{presented}` material"
            ),
            Self::Malformed(why) => write!(f, "malformed credential: {why}"),
            Self::Expired => f.write_str("credential expired"),
            Self::SignatureInvalid => f.write_str("credential signature did not verify"),
            Self::UnknownCredential => f.write_str("unknown credential"),
            Self::Revoked => f.write_str("credential revoked"),
            Self::Backend(why) => write!(f, "authenticator backend error: {why}"),
        }
    }
}

impl std::error::Error for AuthnRejection {}

impl AuthnRejection {
    /// Build an [`Unsupported`](AuthnRejection::Unsupported) rejection.
    pub fn unsupported(authenticator: impl Into<String>, presented: &Presentation) -> Self {
        Self::Unsupported {
            authenticator: authenticator.into(),
            presented: presented.kind_label().to_string(),
        }
    }

    /// Is this "wrong credential kind, try the next authenticator"?
    pub fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported { .. })
    }

    /// Is this an infrastructure failure rather than a rejected caller?
    pub fn is_backend_failure(&self) -> bool {
        matches!(self, Self::Backend(_))
    }
}

/// Proof that some [`Authenticator`] verified credential material, together
/// with what it learned.
///
/// The claims bag carries the tenant *hint* (`org_id`) among other things.
/// It is a hint and not an authorization: tenancy enforcement still routes
/// through [`TenantResolver`](crate::TenantResolver) and
/// [`TenantGate`](crate::TenantGate), and this build does not change that
/// (orgs/membership are M4).
#[derive(Debug, Clone)]
pub struct Authenticated {
    principal: Principal,
    session_id: String,
    roles: Vec<String>,
    claims: Value,
}

impl Authenticated {
    /// Record a successful authentication.
    ///
    /// Called by [`Authenticator`] impls **after** verifying material. The
    /// constructor is public because authenticators live in other crates
    /// (plexus-idp's does), so this type is a convention-backed proof rather
    /// than a crate-sealed one like [`VerifiedUser`](crate::VerifiedUser).
    /// The strong seal is deliberately deferred: making it crate-private here
    /// would make the trait unimplementable outside `plexus-auth-core`, which
    /// is exactly the pluggability this build exists to add.
    pub fn new(
        principal: Principal,
        session_id: impl Into<String>,
        roles: Vec<String>,
        claims: Value,
    ) -> Self {
        Self {
            principal,
            session_id: session_id.into(),
            roles,
            claims,
        }
    }

    /// The verified subject.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The session identifier, empty for stateless credentials (JWTs, API
    /// keys) exactly as today's validators leave it.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Roles asserted by the credential.
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Additional verified claims (`org_id`, `username`, …).
    pub fn claims(&self) -> &Value {
        &self.claims
    }

    /// Project this proof into the runtime [`AuthContext`].
    ///
    /// This is the one place the two identity representations are tied
    /// together, and it is why they cannot diverge:
    ///
    /// - `user_id` is [`Principal::as_legacy_user_id`] — for an idp
    ///   principal that is the bare UUID, byte-identical to what plexus-idp
    ///   writes today.
    /// - the full namespaced principal is stamped into
    ///   `metadata["principal"]`.
    ///
    /// [`AuthContext::principal`] reads the stamp back, and falls back to
    /// re-deriving it from `user_id` when the stamp is absent (a context
    /// built by an older code path). Both routes yield the same value for an
    /// idp principal — see the `principal_and_user_id_agree_*` tests.
    pub fn into_auth_context(self) -> AuthContext {
        let Self {
            principal,
            session_id,
            roles,
            claims,
        } = self;

        let mut metadata: Map<String, Value> = match claims {
            Value::Object(m) => m,
            Value::Null => Map::new(),
            // A non-object claims payload is preserved rather than dropped:
            // discarding verified claims silently would be worse than an
            // odd-shaped metadata bag.
            other => {
                let mut m = Map::new();
                m.insert("claims".to_string(), other);
                m
            }
        };
        metadata.insert(
            PRINCIPAL_CLAIM.to_string(),
            Value::String(principal.to_string()),
        );

        AuthContext::new(
            principal.as_legacy_user_id(),
            session_id,
            roles,
            Value::Object(metadata),
        )
    }
}

/// One credential kind's verifier.
///
/// Implementations live wherever the verification material does — plexus-idp
/// implements one over its own signing keys, a nostr gateway would implement
/// one over secp256k1 — and are composed by an [`AuthenticatorChain`].
///
/// # Contract
///
/// - `accepts` must be cheap and side-effect free. It is a routing hint; a
///   `true` from it does not oblige `authenticate` to succeed.
/// - `authenticate` must return
///   [`Unsupported`](AuthnRejection::Unsupported) if and only if `accepts`
///   would have returned `false`. Any other error means the material was
///   this authenticator's and was rejected.
/// - `authenticate` must not return [`Authenticated`] without having
///   verified the material — that is the whole contract of the type.
#[async_trait]
pub trait Authenticator: Send + Sync + 'static {
    /// A stable, non-secret name for logs, audit records, and capability
    /// advertisement.
    fn name(&self) -> &str;

    /// Does this authenticator handle this presentation?
    fn accepts(&self, presentation: &Presentation) -> bool;

    /// Verify the material and name the subject it proves.
    async fn authenticate(
        &self,
        presentation: &Presentation,
    ) -> Result<Authenticated, AuthnRejection>;
}

/// An ordered set of [`Authenticator`]s tried in turn.
///
/// The chain is what makes "idp is one authenticator among several"
/// structural rather than aspirational: plexus-idp registers its bearer,
/// cookie, and API-key authenticators into a chain, and a nostr gateway would
/// push one more in without any of them knowing about each other.
///
/// # Ordering and short-circuiting
///
/// Authenticators are tried in insertion order. The first one whose
/// `authenticate` returns anything other than
/// [`Unsupported`](AuthnRejection::Unsupported) decides the outcome —
/// success *or* failure. A malformed JWT therefore does not fall through to
/// the API-key authenticator hoping it will be luckier.
#[derive(Clone, Default)]
pub struct AuthenticatorChain {
    authenticators: Vec<Arc<dyn Authenticator>>,
}

impl std::fmt::Debug for AuthenticatorChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatorChain")
            .field("authenticators", &self.names())
            .finish()
    }
}

impl AuthenticatorChain {
    /// An empty chain, which rejects everything.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an authenticator.
    pub fn with(mut self, authenticator: Arc<dyn Authenticator>) -> Self {
        self.authenticators.push(authenticator);
        self
    }

    /// The names of the registered authenticators, in order.
    pub fn names(&self) -> Vec<&str> {
        self.authenticators.iter().map(|a| a.name()).collect()
    }

    /// Is the chain empty?
    pub fn is_empty(&self) -> bool {
        self.authenticators.is_empty()
    }

    /// Try each authenticator in order.
    ///
    /// Returns the first non-`Unsupported` outcome. If every authenticator
    /// declines, the last `Unsupported` is returned (or a synthetic one for
    /// an empty chain), so the caller can tell "nobody handles this" from
    /// "somebody handled it and said no".
    pub async fn authenticate(
        &self,
        presentation: &Presentation,
    ) -> Result<Authenticated, AuthnRejection> {
        let mut last = AuthnRejection::unsupported("<empty chain>", presentation);
        for authenticator in &self.authenticators {
            if !authenticator.accepts(presentation) {
                continue;
            }
            match authenticator.authenticate(presentation).await {
                Ok(ok) => return Ok(ok),
                Err(e) if e.is_unsupported() => last = e,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }
}

/// Adapts a chain to the existing perimeter.
///
/// The cookie header a `SessionValidator` receives is offered to the chain as
/// a [`Presentation::Cookie`]; if no authenticator claims it, it is retried as
/// a [`Presentation::Bearer`], because plexus-idp's validator has always
/// accepted a bare token in the cookie position and callers depend on that.
#[async_trait]
impl SessionValidator for AuthenticatorChain {
    async fn validate(&self, cookie_value: &str) -> Option<AuthContext> {
        let as_cookie = Presentation::Cookie {
            header: cookie_value.to_string(),
        };
        match self.authenticate(&as_cookie).await {
            Ok(ok) => return Some(ok.into_auth_context()),
            Err(e) if !e.is_unsupported() => return None,
            Err(_) => {}
        }

        let as_bearer = Presentation::Bearer {
            token: cookie_value.trim().to_string(),
        };
        self.authenticate(&as_bearer)
            .await
            .ok()
            .map(Authenticated::into_auth_context)
    }
}

// ── Reference authenticators ───────────────────────────────────────────

/// Verified content of a bearer token, as a token verifier reports it.
///
/// Deliberately smaller than a JWT claim set: an [`Authenticator`] needs the
/// subject, the roles, and a claims bag, and nothing about this shape assumes
/// JWT — a verifier backed by token introspection reports the same thing.
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    /// The token's subject, as the issuer wrote it.
    pub subject: String,
    /// Roles asserted by the token, if any.
    pub roles: Vec<String>,
    /// Remaining verified claims (`org_id`, `username`, …).
    pub claims: Value,
}

/// Verifies a bearer token's signature and time window.
///
/// This is the seam that lets [`BearerJwtAuthenticator`] live here while the
/// actual key material lives elsewhere: plexus-idp implements this over its
/// own `KeyStore` and `iss`/`aud` checks, so the bearer authenticator
/// "delegates to today's idp validation" rather than reimplementing it.
#[async_trait]
pub trait TokenVerifier: Send + Sync + 'static {
    /// The issuer whose principals this verifier mints. Fixes the namespace
    /// of the resulting [`Principal`], so a verifier cannot accidentally
    /// vouch for a subject in someone else's namespace.
    fn issuer(&self) -> Issuer;

    /// Verify signature, `iss`/`aud`, and expiry.
    async fn verify(&self, token: &str) -> Result<VerifiedClaims, AuthnRejection>;
}

/// Bearer-token authenticator over an injected [`TokenVerifier`].
pub struct BearerJwtAuthenticator<V: TokenVerifier> {
    name: String,
    verifier: V,
}

impl<V: TokenVerifier> BearerJwtAuthenticator<V> {
    /// Wrap a verifier. `name` appears in logs and audit records.
    pub fn new(name: impl Into<String>, verifier: V) -> Self {
        Self {
            name: name.into(),
            verifier,
        }
    }
}

#[async_trait]
impl<V: TokenVerifier> Authenticator for BearerJwtAuthenticator<V> {
    fn name(&self) -> &str {
        &self.name
    }

    fn accepts(&self, presentation: &Presentation) -> bool {
        matches!(presentation, Presentation::Bearer { .. })
    }

    async fn authenticate(
        &self,
        presentation: &Presentation,
    ) -> Result<Authenticated, AuthnRejection> {
        let Presentation::Bearer { token } = presentation else {
            return Err(AuthnRejection::unsupported(&self.name, presentation));
        };

        let verified = self.verifier.verify(token).await?;
        // The verifier reports a raw subject; the issuer's grammar decides
        // whether it is nameable. A token that verified but whose `sub` is
        // not a legal subject for this issuer is malformed, not authentic.
        let principal = Principal::new(self.verifier.issuer(), verified.subject.clone())
            .map_err(|e| AuthnRejection::Malformed(e.to_string()))?;

        Ok(Authenticated::new(
            principal,
            String::new(),
            verified.roles,
            verified.claims,
        ))
    }
}

/// Digests a raw API key into the locator its
/// [`CredentialLink`] store is keyed by.
///
/// Injected rather than fixed so `plexus-auth-core` need not take a hash
/// dependency, and so a deployment can change digest without changing this
/// crate. plexus-idp passes its existing SHA-256 hex function, which is why
/// the authenticator resolves keys that were stored before this build.
pub type ApiKeyDigest = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// API-key authenticator backed by a [`CredentialLink`] store.
///
/// Resolution is *lookup*, never minting: a key that is not linked to a
/// principal is [`UnknownCredential`](AuthnRejection::UnknownCredential).
/// That is what makes an API key a credential *of* a principal rather than a
/// second identity for the same human.
pub struct ApiKeyAuthenticator {
    name: String,
    links: Arc<dyn CredentialLink>,
    digest: ApiKeyDigest,
}

impl ApiKeyAuthenticator {
    /// Build an authenticator that looks keys up, after digesting them, in
    /// `links`.
    pub fn new(name: impl Into<String>, links: Arc<dyn CredentialLink>, digest: ApiKeyDigest) -> Self {
        Self {
            name: name.into(),
            links,
            digest,
        }
    }

    /// Convenience for stores that key on the raw value (tests, and
    /// deployments that hash before calling).
    pub fn plaintext(name: impl Into<String>, links: Arc<dyn CredentialLink>) -> Self {
        Self::new(name, links, Arc::new(|k: &str| k.to_string()))
    }
}

#[async_trait]
impl Authenticator for ApiKeyAuthenticator {
    fn name(&self) -> &str {
        &self.name
    }

    fn accepts(&self, presentation: &Presentation) -> bool {
        // API keys are commonly presented in the bearer position, so both
        // carriers are accepted. The store lookup is what decides.
        matches!(
            presentation,
            Presentation::ApiKey { .. } | Presentation::Bearer { .. }
        )
    }

    async fn authenticate(
        &self,
        presentation: &Presentation,
    ) -> Result<Authenticated, AuthnRejection> {
        let raw = match presentation {
            Presentation::ApiKey { key } => key,
            Presentation::Bearer { token } => token,
            _ => return Err(AuthnRejection::unsupported(&self.name, presentation)),
        };
        if raw.is_empty() {
            return Err(AuthnRejection::Malformed("empty api key".into()));
        }

        let locator = (self.digest)(raw);
        let link = self
            .links
            .resolve(CredentialClass::ApiKey, &locator)
            .await
            .map_err(|e| AuthnRejection::Backend(e.to_string()))?
            .ok_or(AuthnRejection::UnknownCredential)?;

        if link.is_revoked() {
            return Err(AuthnRejection::Revoked);
        }
        if link.is_expired_at(chrono::Utc::now()) {
            return Err(AuthnRejection::Expired);
        }

        Ok(Authenticated::new(
            link.principal().clone(),
            String::new(),
            link.roles().to_vec(),
            link.claims().clone(),
        ))
    }
}

/// Unwraps a cookie header and re-presents its token to an inner
/// authenticator.
///
/// A cookie is a *carrier*, not a credential kind — the thing inside it is a
/// bearer token or an API key. Modelling it as a decorator rather than a
/// fourth verification algorithm keeps exactly one implementation of each
/// actual proof, which is why this type contains no verification logic at
/// all.
pub struct CookieAuthenticator {
    name: String,
    cookie_name: String,
    inner: Arc<dyn Authenticator>,
    /// Accept a value with no `=` as a bare token, as plexus-idp always has.
    allow_bare_token: bool,
}

impl CookieAuthenticator {
    /// Extract `cookie_name` from the header and hand it to `inner`.
    pub fn new(
        name: impl Into<String>,
        cookie_name: impl Into<String>,
        inner: Arc<dyn Authenticator>,
    ) -> Self {
        Self {
            name: name.into(),
            cookie_name: cookie_name.into(),
            inner,
            allow_bare_token: true,
        }
    }

    /// Require a real cookie pair; reject a bare token in the cookie
    /// position.
    pub fn strict(mut self) -> Self {
        self.allow_bare_token = false;
        self
    }

    /// Pull the configured cookie's value out of a `Cookie:` header.
    fn extract<'a>(&self, header: &'a str) -> Option<&'a str> {
        if !header.contains('=') {
            return self.allow_bare_token.then(|| header.trim());
        }
        for pair in header.split(';') {
            let pair = pair.trim();
            if let Some(rest) = pair.strip_prefix(&self.cookie_name) {
                if let Some(val) = rest.strip_prefix('=') {
                    return Some(val.trim());
                }
            }
        }
        None
    }
}

#[async_trait]
impl Authenticator for CookieAuthenticator {
    fn name(&self) -> &str {
        &self.name
    }

    fn accepts(&self, presentation: &Presentation) -> bool {
        matches!(presentation, Presentation::Cookie { .. })
    }

    async fn authenticate(
        &self,
        presentation: &Presentation,
    ) -> Result<Authenticated, AuthnRejection> {
        let Presentation::Cookie { header } = presentation else {
            return Err(AuthnRejection::unsupported(&self.name, presentation));
        };

        let token = self.extract(header).ok_or_else(|| {
            AuthnRejection::Malformed(format!("no `{}` cookie in header", self.cookie_name))
        })?;
        if token.is_empty() {
            return Err(AuthnRejection::Malformed(format!(
                "`{}` cookie is empty",
                self.cookie_name
            )));
        }

        let inner = Presentation::Bearer {
            token: token.to_string(),
        };
        match self.inner.authenticate(&inner).await {
            // Translate the inner authenticator's "not my kind" into this
            // one's, so a chain sees a consistent story about the cookie.
            Err(e) if e.is_unsupported() => {
                Err(AuthnRejection::unsupported(&self.name, presentation))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::linking::{InMemoryCredentialLink, LinkedCredential};

    const UUID: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

    struct FakeIdp;

    #[async_trait]
    impl TokenVerifier for FakeIdp {
        fn issuer(&self) -> Issuer {
            Issuer::Idp
        }
        async fn verify(&self, token: &str) -> Result<VerifiedClaims, AuthnRejection> {
            match token {
                "good" => Ok(VerifiedClaims {
                    subject: UUID.to_string(),
                    roles: vec!["user".into()],
                    claims: serde_json::json!({"org_id": "acme"}),
                }),
                "stale" => Err(AuthnRejection::Expired),
                "notauuid" => Ok(VerifiedClaims {
                    subject: "alice".to_string(),
                    roles: vec![],
                    claims: Value::Null,
                }),
                _ => Err(AuthnRejection::SignatureInvalid),
            }
        }
    }

    fn bearer(t: &str) -> Presentation {
        Presentation::Bearer {
            token: t.to_string(),
        }
    }

    #[tokio::test]
    async fn bearer_authenticator_produces_a_verified_principal() {
        let a = BearerJwtAuthenticator::new("idp-bearer", FakeIdp);
        let ok = a.authenticate(&bearer("good")).await.unwrap();
        assert_eq!(ok.principal().to_string(), format!("idp:{UUID}"));
        assert_eq!(ok.roles(), ["user"]);
    }

    #[tokio::test]
    async fn bearer_authenticator_rejects_with_typed_errors() {
        let a = BearerJwtAuthenticator::new("idp-bearer", FakeIdp);
        assert_eq!(
            a.authenticate(&bearer("stale")).await.unwrap_err(),
            AuthnRejection::Expired
        );
        assert_eq!(
            a.authenticate(&bearer("forged")).await.unwrap_err(),
            AuthnRejection::SignatureInvalid
        );
        // Verified, but the subject is not nameable in the idp namespace.
        assert!(matches!(
            a.authenticate(&bearer("notauuid")).await.unwrap_err(),
            AuthnRejection::Malformed(_)
        ));
        // Wrong carrier entirely.
        assert!(a
            .authenticate(&Presentation::ApiKey { key: "x".into() })
            .await
            .unwrap_err()
            .is_unsupported());
    }

    async fn links_with_key() -> Arc<InMemoryCredentialLink> {
        let links = Arc::new(InMemoryCredentialLink::new());
        let p: Principal = format!("idp:{UUID}").parse().unwrap();
        links
            .link(
                LinkedCredential::new(CredentialClass::ApiKey, "digest-of-k1", p)
                    .with_roles(vec!["service".into()]),
            )
            .await
            .unwrap();
        links
    }

    #[tokio::test]
    async fn api_key_authenticator_resolves_and_rejects() {
        let links = links_with_key().await;
        let a = ApiKeyAuthenticator::new(
            "apikey",
            links.clone(),
            Arc::new(|k: &str| format!("digest-of-{k}")),
        );

        let ok = a
            .authenticate(&Presentation::ApiKey { key: "k1".into() })
            .await
            .unwrap();
        assert_eq!(ok.principal().to_string(), format!("idp:{UUID}"));
        assert_eq!(ok.roles(), ["service"]);

        assert_eq!(
            a.authenticate(&Presentation::ApiKey { key: "nope".into() })
                .await
                .unwrap_err(),
            AuthnRejection::UnknownCredential
        );
        assert!(matches!(
            a.authenticate(&Presentation::ApiKey { key: "".into() })
                .await
                .unwrap_err(),
            AuthnRejection::Malformed(_)
        ));
    }

    #[tokio::test]
    async fn api_key_authenticator_honours_revocation_and_expiry() {
        let links = Arc::new(InMemoryCredentialLink::new());
        let p: Principal = format!("idp:{UUID}").parse().unwrap();
        links
            .link(LinkedCredential::new(CredentialClass::ApiKey, "dead", p.clone()).revoked())
            .await
            .unwrap();
        links
            .link(
                LinkedCredential::new(CredentialClass::ApiKey, "old", p)
                    .expiring_at(chrono::Utc::now() - chrono::Duration::hours(1)),
            )
            .await
            .unwrap();

        let a = ApiKeyAuthenticator::plaintext("apikey", links);
        assert_eq!(
            a.authenticate(&Presentation::ApiKey { key: "dead".into() })
                .await
                .unwrap_err(),
            AuthnRejection::Revoked
        );
        assert_eq!(
            a.authenticate(&Presentation::ApiKey { key: "old".into() })
                .await
                .unwrap_err(),
            AuthnRejection::Expired
        );
    }

    #[tokio::test]
    async fn cookie_authenticator_unwraps_and_delegates() {
        let inner = Arc::new(BearerJwtAuthenticator::new("idp-bearer", FakeIdp));
        let a = CookieAuthenticator::new("idp-cookie", "access_token", inner);

        let ok = a
            .authenticate(&Presentation::Cookie {
                header: "theme=dark; access_token=good; other=1".into(),
            })
            .await
            .unwrap();
        assert_eq!(ok.principal().to_string(), format!("idp:{UUID}"));

        // Bare token in the cookie position, as plexus-idp has always allowed.
        let ok = a
            .authenticate(&Presentation::Cookie {
                header: "good".into(),
            })
            .await
            .unwrap();
        assert_eq!(ok.principal().to_string(), format!("idp:{UUID}"));

        // Missing cookie is malformed; a bad token inside surfaces the inner
        // error unchanged.
        assert!(matches!(
            a.authenticate(&Presentation::Cookie {
                header: "theme=dark".into()
            })
            .await
            .unwrap_err(),
            AuthnRejection::Malformed(_)
        ));
        assert_eq!(
            a.authenticate(&Presentation::Cookie {
                header: "access_token=stale".into()
            })
            .await
            .unwrap_err(),
            AuthnRejection::Expired
        );
    }

    #[tokio::test]
    async fn cookie_extraction_does_not_match_a_suffix_cookie() {
        let inner = Arc::new(BearerJwtAuthenticator::new("idp-bearer", FakeIdp));
        let a = CookieAuthenticator::new("idp-cookie", "access_token", inner);
        // `xaccess_token` must not be mistaken for `access_token`.
        let err = a
            .authenticate(&Presentation::Cookie {
                header: "xaccess_token=good".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AuthnRejection::Malformed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn chain_short_circuits_on_a_real_failure() {
        let links = links_with_key().await;
        let chain = AuthenticatorChain::new()
            .with(Arc::new(BearerJwtAuthenticator::new("idp-bearer", FakeIdp)))
            .with(Arc::new(ApiKeyAuthenticator::plaintext("apikey", links)));

        assert_eq!(chain.names(), ["idp-bearer", "apikey"]);

        // The bearer authenticator claims and fails; the API-key
        // authenticator must NOT get a second chance at an expired token.
        assert_eq!(
            chain.authenticate(&bearer("stale")).await.unwrap_err(),
            AuthnRejection::Expired
        );
    }

    #[tokio::test]
    async fn empty_chain_reports_unsupported_not_success() {
        let chain = AuthenticatorChain::new();
        assert!(chain.is_empty());
        assert!(chain
            .authenticate(&bearer("good"))
            .await
            .unwrap_err()
            .is_unsupported());
        assert!(chain.validate("anything").await.is_none());
    }

    #[tokio::test]
    async fn chain_is_a_session_validator() {
        let chain = AuthenticatorChain::new().with(Arc::new(CookieAuthenticator::new(
            "idp-cookie",
            "access_token",
            Arc::new(BearerJwtAuthenticator::new("idp-bearer", FakeIdp)),
        )));

        let ctx = chain.validate("access_token=good").await.unwrap();
        assert_eq!(ctx.user_id, UUID);
        assert_eq!(
            ctx.principal().map(|p| p.to_string()),
            Some(format!("idp:{UUID}"))
        );
        assert!(chain.validate("access_token=forged").await.is_none());
    }
}
