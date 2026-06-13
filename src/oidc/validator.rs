//! `OidcValidator` — RS256 token validation against a discovered JWKS
//! (UT-1, UT-S01 D1; caching per AUTH-8; test matrix per AUTH-2).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use url::Url;

use crate::auth::AuthContext;
use crate::oidc::config::OidcConfig;
use crate::oidc::fetch::JwksFetcher;
use crate::oidc::jwks;
use crate::tenant::types::{TenantError, TenantId};
use crate::verified_user::VerifiedUser;

/// Validation failure modes.
///
/// The matrix-relevant rejections (`Expired`, `WrongIssuer`,
/// `WrongAudience`, `InvalidSignature`, `UnknownKeyId`) are distinct
/// variants so backends can log precisely; all of them must collapse to
/// one generic auth failure on the wire (no oracle about *why* a token
/// was rejected). `SessionValidator` impls do this naturally by
/// returning `None`.
#[derive(Debug)]
pub enum OidcError {
    /// Discovery document could not be fetched / parsed / trusted, and no
    /// previously discovered `jwks_uri` was cached.
    Discovery(String),
    /// JWKS could not be fetched and no cached keys exist (cold cache +
    /// unreachable IdP). With a warm cache the validator degrades instead
    /// of erroring — see the module-level caching policy.
    JwksUnavailable(String),
    /// The token header carries no `kid`. The UT-S01 IdP contract is
    /// "signs RS256 with `kid`"; kid-less tokens are rejected outright.
    MissingKeyId,
    /// The token's `kid` is not in the JWKS even after the policy's one
    /// unconditional refresh.
    UnknownKeyId(String),
    /// The token's `alg` is not RS256 (RS256-only posture; the EdDSA
    /// extension lands here and in `jwks::admit_key`).
    UnsupportedAlgorithm(String),
    /// Signature verification failed (tampered or foreign-key token).
    InvalidSignature,
    /// `exp` is in the past. Zero leeway — no grace (AUTH-8), online or
    /// offline.
    Expired,
    /// `iss` does not match the configured issuer.
    WrongIssuer,
    /// `aud` does not match the configured audience.
    WrongAudience,
    /// `iat` is in the future (zero leeway).
    IssuedInFuture {
        /// The token's `iat`.
        iat: i64,
        /// The validator's clock at check time.
        now: i64,
    },
    /// The token is structurally broken (not a JWT, undecodable claims,
    /// missing required claims).
    MalformedToken(String),
    /// The token carried an `org_id` claim that fails [`TenantId`]
    /// validation. Rejected rather than treated as tenantless: a
    /// malformed tenant claim must not silently widen (or collapse) the
    /// caller's isolation scope.
    InvalidTenantClaim(TenantError),
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(m) => write!(f, "OIDC discovery failed: {m}"),
            Self::JwksUnavailable(m) => write!(f, "JWKS unavailable and no cached keys: {m}"),
            Self::MissingKeyId => f.write_str("token header carries no kid"),
            Self::UnknownKeyId(kid) => {
                write!(f, "kid {kid:?} not in JWKS after one refresh")
            }
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported token algorithm {alg} (RS256-only)")
            }
            Self::InvalidSignature => f.write_str("token signature invalid"),
            Self::Expired => f.write_str("token expired (exp in the past, zero leeway)"),
            Self::WrongIssuer => f.write_str("token iss does not match configured issuer"),
            Self::WrongAudience => f.write_str("token aud does not match configured audience"),
            Self::IssuedInFuture { iat, now } => {
                write!(f, "token iat {iat} is in the future (now {now})")
            }
            Self::MalformedToken(m) => write!(f, "malformed token: {m}"),
            Self::InvalidTenantClaim(e) => write!(f, "invalid org_id claim: {e}"),
        }
    }
}

impl std::error::Error for OidcError {}

/// The claims the validator reads. Standard five plus the tenancy claim
/// and the optional plexus extensions (UT-S01 D2 negative space: `roles`
/// / `username` must be optional for validation — and they are).
///
/// `aud` is deliberately absent here: audience matching is enforced by
/// `jsonwebtoken`'s `Validation` (which handles both string and
/// string-array forms); the value itself is not needed afterwards.
#[derive(Debug, Deserialize)]
struct OidcClaims {
    sub: String,
    iss: String,
    exp: i64,
    iat: i64,
    /// Tenancy claim (UT-S01 D3 — Auth0 Organizations convention).
    #[serde(default)]
    org_id: Option<String>,
    /// OIDC session id, used for `AuthContext::session_id` when present.
    #[serde(default)]
    sid: Option<String>,
    /// JWT id — `session_id` fallback when `sid` is absent.
    #[serde(default)]
    jti: Option<String>,
    /// Plexus extension; optional for validation.
    #[serde(default)]
    roles: Option<Vec<String>>,
    /// Plexus extension; optional for validation.
    #[serde(default)]
    username: Option<String>,
}

/// The OIDC discovery document fields the validator needs.
#[derive(Debug, Deserialize)]
struct DiscoveryDoc {
    issuer: String,
    jwks_uri: String,
}

/// JWKS cache state, guarded by a `std::sync::Mutex` that is **never
/// held across an await** (lock → copy/update → drop; fetches happen
/// unlocked). Concurrent kid-miss validations may therefore race into
/// concurrent refreshes — harmless: the policy bound ("exactly one
/// refresh") is per validation call, not global.
struct CacheState {
    /// Discovered `jwks_uri`. Cached for the validator's lifetime once
    /// resolved; refreshed only if a later refresh cycle needs it again.
    jwks_uri: Option<Url>,
    /// kid → verification key.
    keys: HashMap<String, DecodingKey>,
    /// When the keys were last successfully fetched. `None` ⇔ cold.
    fetched_at: Option<Instant>,
    /// TTL derived from the JWKS response's `Cache-Control` (AUTH-8:
    /// min(max-age, 3600 s)).
    ttl: Duration,
    /// Whether the validator is in degraded (stale-cache) mode. Drives
    /// the `auth_provider_degraded` / `auth_provider_restored` event
    /// transitions.
    degraded: bool,
}

/// Outcome of a refresh attempt.
#[derive(Clone, Copy, PartialEq)]
enum RefreshOutcome {
    /// Fresh keys fetched and stored.
    Fresh,
    /// Fetch failed but cached keys exist — validation proceeds with the
    /// stale cache (degraded mode).
    Degraded,
}

/// Locally validates RS256 tokens issued by one trusted OIDC issuer.
///
/// See the [module docs](crate::oidc) for the resolution model, caching
/// policy, and interchangeability bar. Construction:
///
/// - [`OidcValidator::with_fetcher`] — inject any [`JwksFetcher`]
///   (tests, custom HTTP stacks).
/// - `OidcValidator::new` — batteries-included `reqwest` fetcher;
///   requires the `oidc-reqwest` feature.
///
/// The validator is `Send + Sync`; share one instance per backend (the
/// JWKS cache lives inside it).
pub struct OidcValidator {
    config: OidcConfig,
    fetcher: Arc<dyn JwksFetcher>,
    state: Mutex<CacheState>,
}

impl OidcValidator {
    /// Build a validator with the default `reqwest` fetcher.
    #[cfg(feature = "oidc-reqwest")]
    pub fn new(config: OidcConfig) -> Self {
        Self::with_fetcher(config, Arc::new(crate::oidc::fetch::ReqwestJwksFetcher::new()))
    }

    /// Build a validator over an injected fetcher.
    pub fn with_fetcher(config: OidcConfig, fetcher: Arc<dyn JwksFetcher>) -> Self {
        Self {
            config,
            fetcher,
            state: Mutex::new(CacheState {
                jwks_uri: None,
                keys: HashMap::new(),
                fetched_at: None,
                ttl: Duration::from_secs(0),
                degraded: false,
            }),
        }
    }

    /// The validator's configuration.
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// Validate a token end-to-end and mint the sealed proof.
    ///
    /// Steps: header gate (`alg` == RS256, `kid` present) → cache
    /// freshness (refresh on cold/expired TTL; degrade to stale keys if
    /// the IdP is unreachable and a cache exists) → kid lookup (miss →
    /// exactly one unconditional refresh, then reject) → RS256 signature
    /// + `iss`/`aud`/`exp` with zero leeway → `iat` not in the future →
    /// `org_id` → [`TenantId`] → [`VerifiedUser`] minted.
    pub async fn validate_token(&self, token: &str) -> Result<VerifiedToken, OidcError> {
        // ── Header gate ───────────────────────────────────────────────
        let header =
            decode_header(token).map_err(|e| OidcError::MalformedToken(e.to_string()))?;
        if header.alg != Algorithm::RS256 {
            return Err(OidcError::UnsupportedAlgorithm(format!("{:?}", header.alg)));
        }
        let kid = header.kid.ok_or(OidcError::MissingKeyId)?;

        // ── Cache freshness ───────────────────────────────────────────
        let needs_refresh = {
            let st = self.state.lock().unwrap();
            st.fetched_at.is_none_or(|at| at.elapsed() >= st.ttl)
        };
        let mut refresh_attempted = false;
        if needs_refresh {
            self.refresh().await?;
            refresh_attempted = true;
        }

        // ── Key selection (kid-miss → one refresh — AUTH-8) ───────────
        let key = match self.lookup(&kid) {
            Some(k) => k,
            None => {
                if !refresh_attempted {
                    // The one unconditional refresh the policy grants a
                    // kid-miss (key-rotation case: a new kid published
                    // inside the TTL window). If this call already
                    // refreshed above, that refresh *was* the one.
                    self.refresh().await?;
                }
                self.lookup(&kid).ok_or(OidcError::UnknownKeyId(kid.clone()))?
            }
        };

        // ── Signature + standard claims ───────────────────────────────
        let mut validation = Validation::new(Algorithm::RS256);
        // No grace anywhere (AUTH-8): default leeway is 60 s — zero it.
        validation.leeway = 0;
        // Trailing-slash tolerance: `Url` normalizes a root issuer to a
        // trailing slash while many IdPs mint `iss` without one (and
        // Auth0 mints *with* one). Both spellings of the *same* issuer
        // are accepted; any other issuer fails.
        let issuer_str = self.config.issuer().as_url().as_str();
        validation.set_issuer(&[issuer_str, issuer_str.trim_end_matches('/')]);
        validation.set_audience(&[self.config.audience().as_str()]);
        validation.set_required_spec_claims(&["sub", "exp", "iss", "aud"]);

        let data = decode::<OidcClaims>(token, &key, &validation).map_err(map_jwt_error)?;
        let claims = data.claims;

        // ── iat: required by OidcClaims' non-optional field; must not be
        //    in the future (zero leeway, symmetric with exp). ───────────
        let now = chrono::Utc::now().timestamp();
        if claims.iat > now {
            return Err(OidcError::IssuedInFuture { iat: claims.iat, now });
        }

        // ── Tenancy (UT-S01 D3): org_id → TenantId; absent claim ⇒
        //    valid-but-tenantless; malformed claim ⇒ reject. ───────────
        let tenant = claims
            .org_id
            .as_deref()
            .map(TenantId::try_new)
            .transpose()
            .map_err(OidcError::InvalidTenantClaim)?;

        // ── session_id: AuthContext::is_authenticated() requires a
        //    non-empty session_id; prefer the OIDC `sid`, then `jti`,
        //    then the token's signature segment (stable per token,
        //    non-empty for any signed JWT). ─────────────────────────────
        let session_id = claims
            .sid
            .clone()
            .or_else(|| claims.jti.clone())
            .unwrap_or_else(|| token.rsplit('.').next().unwrap_or_default().to_string());

        let user = VerifiedUser::new_sealed(
            claims.sub,
            claims.iss,
            claims.iat,
            claims.exp,
            tenant,
        );

        Ok(VerifiedToken {
            user,
            roles: claims.roles.unwrap_or_default(),
            username: claims.username,
            session_id,
        })
    }

    /// Clone the key for `kid` out of the cache (lock scope stays tiny;
    /// `DecodingKey` is cheaply clonable).
    fn lookup(&self, kid: &str) -> Option<DecodingKey> {
        self.state.lock().unwrap().keys.get(kid).cloned()
    }

    /// Refresh the JWKS (discovering `jwks_uri` first if needed).
    ///
    /// - Success → fresh keys + TTL stored; if the validator was
    ///   degraded, emit `auth_provider_restored`.
    /// - Failure with cached keys → flip to degraded (emit
    ///   `auth_provider_degraded` on the transition), keep serving the
    ///   stale cache. Cached keys remain usable only for tokens whose
    ///   `exp` is still in the future, because `exp` is enforced with
    ///   zero grace regardless (AUTH-8).
    /// - Failure with no cache → error.
    async fn refresh(&self) -> Result<RefreshOutcome, OidcError> {
        match self.try_fetch_keys().await {
            Ok((keys, ttl, jwks_uri)) => {
                let mut st = self.state.lock().unwrap();
                if st.degraded {
                    tracing::info!(
                        target: "plexus::auth",
                        issuer = %self.config.issuer(),
                        "auth_provider_restored: JWKS refresh succeeded; leaving degraded mode"
                    );
                }
                st.keys = keys;
                st.ttl = ttl;
                st.fetched_at = Some(Instant::now());
                st.jwks_uri = Some(jwks_uri);
                st.degraded = false;
                Ok(RefreshOutcome::Fresh)
            }
            Err(err) => {
                let mut st = self.state.lock().unwrap();
                if st.keys.is_empty() {
                    return Err(err);
                }
                if !st.degraded {
                    st.degraded = true;
                    tracing::warn!(
                        target: "plexus::auth",
                        issuer = %self.config.issuer(),
                        error = %err,
                        "auth_provider_degraded: IdP unreachable; serving cached JWKS \
                         (future-exp tokens only — exp has no grace)"
                    );
                }
                Ok(RefreshOutcome::Degraded)
            }
        }
    }

    /// Fetch (and, if needed, discover) the JWKS. Pure fetch+parse; no
    /// state mutation — the caller decides how the result lands.
    async fn try_fetch_keys(
        &self,
    ) -> Result<(HashMap<String, DecodingKey>, Duration, Url), OidcError> {
        let cached_uri = self.state.lock().unwrap().jwks_uri.clone();
        let jwks_uri = match cached_uri {
            Some(u) => u,
            None => self.discover().await?,
        };

        let doc = self
            .fetcher
            .fetch(&jwks_uri)
            .await
            .map_err(|e| OidcError::JwksUnavailable(e.to_string()))?;
        let keys = jwks::parse_jwks(&doc.body).map_err(OidcError::JwksUnavailable)?;
        let ttl = jwks::ttl_from_cache_control(doc.cache_control.as_deref());
        Ok((keys, ttl, jwks_uri))
    }

    /// Fetch the discovery document and extract a trusted `jwks_uri`.
    ///
    /// The document's `issuer` must equal the configured issuer (OIDC
    /// Discovery §4.3 — defends against a misrouted or spoofed discovery
    /// host), trailing-slash tolerant.
    async fn discover(&self) -> Result<Url, OidcError> {
        let url = self.config.discovery_url();
        let doc = self
            .fetcher
            .fetch(&url)
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        let parsed: DiscoveryDoc = serde_json::from_str(&doc.body)
            .map_err(|e| OidcError::Discovery(format!("discovery document parse error: {e}")))?;

        let configured = self.config.issuer().as_url().as_str().trim_end_matches('/');
        if parsed.issuer.trim_end_matches('/') != configured {
            return Err(OidcError::Discovery(format!(
                "discovery document issuer {:?} does not match configured issuer {:?}",
                parsed.issuer, configured
            )));
        }

        Url::parse(&parsed.jwks_uri)
            .map_err(|e| OidcError::Discovery(format!("invalid jwks_uri: {e}")))
    }
}

/// Map `jsonwebtoken` failures onto the matrix-relevant variants.
fn map_jwt_error(e: jsonwebtoken::errors::Error) -> OidcError {
    use jsonwebtoken::errors::ErrorKind;
    match e.kind() {
        ErrorKind::ExpiredSignature => OidcError::Expired,
        ErrorKind::InvalidIssuer => OidcError::WrongIssuer,
        ErrorKind::InvalidAudience => OidcError::WrongAudience,
        ErrorKind::InvalidSignature => OidcError::InvalidSignature,
        _ => OidcError::MalformedToken(e.to_string()),
    }
}

/// The successful outcome of [`OidcValidator::validate_token`].
///
/// Wraps the sealed [`VerifiedUser`] proof together with the optional
/// plexus extension claims a backend may want for its `AuthContext`.
/// Sealed like the proof it carries: no public constructor, no public
/// fields — the only mint path is the validator.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    user: VerifiedUser,
    roles: Vec<String>,
    username: Option<String>,
    session_id: String,
}

impl VerifiedToken {
    /// The sealed proof (claims: `sub`, `iss`, `iat`, `exp`, tenant).
    pub fn user(&self) -> &VerifiedUser {
        &self.user
    }

    /// The verified tenant identity from `org_id`, if the token carried
    /// one. `None` ⇔ valid-but-tenantless (UT-S01 D3).
    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.user.tenant_id()
    }

    /// The `roles` extension claim (empty when absent — optional for
    /// validation per the interchangeability bar).
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// The `username` extension claim, if present.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// The session identifier (`sid`, else `jti`, else the token's
    /// signature segment). Always non-empty, so the
    /// [`AuthContext`] built from this token reports
    /// `is_authenticated() == true`.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Build the per-connection [`AuthContext`].
    ///
    /// Metadata written:
    ///
    /// - `org_id` **and** `tenant_id` — the same value under both keys
    ///   for one deprecation window (UT-S01 D3), so pre-cutover
    ///   `ClaimTenantResolver` configurations keep resolving;
    /// - `iss` — the verified issuer;
    /// - `username` — when the extension claim was present;
    /// - `auth_method: "oidc"` — parity with the API-key path's
    ///   `auth_method` marker in the trak reference.
    pub fn into_auth_context(self) -> AuthContext {
        let mut metadata = serde_json::Map::new();
        if let Some(t) = self.user.tenant_id() {
            let v = serde_json::Value::String(t.as_str().to_string());
            metadata.insert("org_id".into(), v.clone());
            // Deprecation alias — remove after one release window
            // (UT-S01 D3).
            metadata.insert("tenant_id".into(), v);
        }
        metadata.insert(
            "iss".into(),
            serde_json::Value::String(self.user.issuer().to_string()),
        );
        if let Some(u) = &self.username {
            metadata.insert("username".into(), serde_json::Value::String(u.clone()));
        }
        metadata.insert(
            "auth_method".into(),
            serde_json::Value::String("oidc".into()),
        );

        AuthContext::new(
            self.user.user_id().to_string(),
            self.session_id,
            self.roles,
            serde_json::Value::Object(metadata),
        )
    }
}
