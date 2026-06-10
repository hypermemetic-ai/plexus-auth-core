//! `JwksFetcher` — the validator's HTTP seam (UT-1).
//!
//! The OIDC validator never talks HTTP directly; it asks a `JwksFetcher`
//! for documents. This is what makes the AUTH-2 test matrix runnable with
//! **no network**: tests inject a fixture fetcher serving a canned
//! discovery document and JWKS. Production deployments either enable the
//! `oidc-reqwest` feature for the batteries-included
//! [`ReqwestJwksFetcher`] or adapt their own HTTP stack to the trait.

use async_trait::async_trait;
use std::fmt;
use url::Url;

/// A fetched HTTP document plus the caching metadata the AUTH-8 policy
/// needs.
///
/// Plain-data DTO (public fields, like `AuthContext`): it carries no
/// authority — the validator independently validates everything it reads
/// from the body.
#[derive(Debug, Clone)]
pub struct FetchedDocument {
    /// The response body (UTF-8 text; both discovery docs and JWKS are
    /// JSON).
    pub body: String,
    /// The raw `Cache-Control` response header, if the server sent one.
    /// The validator derives the JWKS TTL from its `max-age` directive,
    /// clamped to 3600 s (AUTH-8).
    pub cache_control: Option<String>,
}

/// A fetch failure. Single-variant-with-message by design: the validator
/// treats every fetch failure identically (degrade if a cache exists,
/// reject otherwise) — distinguishing DNS from TLS from 503 buys nothing
/// at this layer, and the message is preserved for the operator log.
#[derive(Debug, Clone)]
pub struct FetchError(pub String);

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fetch failed: {}", self.0)
    }
}

impl std::error::Error for FetchError {}

/// Async document fetcher for OIDC discovery and JWKS documents.
///
/// `Send + Sync + 'static` because the validator is shared across
/// concurrent requests (same bounds rationale as
/// [`SessionValidator`](crate::SessionValidator)).
#[async_trait]
pub trait JwksFetcher: Send + Sync + 'static {
    /// GET the document at `url`.
    ///
    /// Implementations should treat non-2xx statuses as `Err` — the
    /// validator never wants an error page parsed as a key set.
    async fn fetch(&self, url: &Url) -> Result<FetchedDocument, FetchError>;
}

/// Batteries-included fetcher over `reqwest` (feature `oidc-reqwest`).
///
/// Uses rustls; a 10-second total timeout keeps a wedged IdP from
/// stalling the request path longer than the degraded-cache policy
/// already tolerates.
#[cfg(feature = "oidc-reqwest")]
pub struct ReqwestJwksFetcher {
    client: reqwest::Client,
}

#[cfg(feature = "oidc-reqwest")]
impl ReqwestJwksFetcher {
    /// Build with a default 10 s timeout client.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client with static config always builds"),
        }
    }

    /// Build over a caller-supplied client (custom proxy/timeout/TLS
    /// posture).
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[cfg(feature = "oidc-reqwest")]
impl Default for ReqwestJwksFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "oidc-reqwest")]
#[async_trait]
impl JwksFetcher for ReqwestJwksFetcher {
    async fn fetch(&self, url: &Url) -> Result<FetchedDocument, FetchError> {
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| FetchError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FetchError(format!("{url}: HTTP {}", resp.status())));
        }
        let cache_control = resp
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = resp.text().await.map_err(|e| FetchError(e.to_string()))?;
        Ok(FetchedDocument { body, cache_control })
    }
}
