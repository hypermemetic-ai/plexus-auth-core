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

/// The most a discovery document or JWKS may weigh (IDENTITY-27). Real
/// ones are a few KiB; anything past this is refused rather than read.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Batteries-included fetcher over `reqwest` (feature `oidc-reqwest`).
///
/// Uses rustls; a 10-second total timeout keeps a wedged IdP from
/// stalling the request path longer than the degraded-cache policy
/// already tolerates. IDENTITY-27: redirects are not followed (a 3xx is a
/// failure — the issuer's documents live where discovery says), and a body
/// over [`MAX_DOCUMENT_BYTES`] is refused without being read past the cap.
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
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client with static config always builds"),
        }
    }

    /// Build over a caller-supplied client (custom proxy/timeout/TLS
    /// posture). The body cap still applies; the redirect policy is the
    /// client's — build it with `redirect::Policy::none()` to keep the
    /// default's posture.
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
        if resp.content_length().is_some_and(|n| n > MAX_DOCUMENT_BYTES as u64) {
            return Err(FetchError(format!("{url}: body over {MAX_DOCUMENT_BYTES} bytes")));
        }
        let mut resp = resp;
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| FetchError(e.to_string()))? {
            if bytes.len() + chunk.len() > MAX_DOCUMENT_BYTES {
                return Err(FetchError(format!("{url}: body over {MAX_DOCUMENT_BYTES} bytes")));
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(bytes).map_err(|e| FetchError(format!("{url}: {e}")))?;
        Ok(FetchedDocument { body, cache_control })
    }
}

#[cfg(all(test, feature = "oidc-reqwest"))]
mod tests {
    //! IDENTITY-27: the reqwest fetcher against a one-shot local HTTP
    //! server (an ephemeral loopback port).
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serve `response` (status line, headers and body) to every
    /// connection; count the connections.
    async fn serve(response: Vec<u8>) -> (Url, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let response = response.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(&response).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (format!("http://{addr}/jwks.json").parse().unwrap(), hits)
    }

    fn http(status: &str, headers: &str, body: &[u8], length: bool) -> Vec<u8> {
        let mut r = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{headers}");
        if length {
            r.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        r.push_str("\r\n");
        let mut r = r.into_bytes();
        r.extend_from_slice(body);
        r
    }

    #[tokio::test]
    async fn a_small_document_is_read_with_its_cache_control() {
        let (url, _) = serve(http("200 OK", "Cache-Control: max-age=120\r\n", br#"{"keys":[]}"#, true)).await;
        let doc = ReqwestJwksFetcher::new().fetch(&url).await.unwrap();
        assert_eq!(doc.body, r#"{"keys":[]}"#);
        assert_eq!(doc.cache_control.as_deref(), Some("max-age=120"));
    }

    #[tokio::test]
    async fn an_oversized_body_is_refused() {
        let big = vec![b' '; MAX_DOCUMENT_BYTES + 1];
        // Declared too large…
        let (url, _) = serve(http("200 OK", "", &big, true)).await;
        let err = ReqwestJwksFetcher::new().fetch(&url).await.unwrap_err();
        assert!(err.0.contains("bytes"), "{err}");
        // …and undeclared (read until the connection closes): cut at the cap.
        let (url, _) = serve(http("200 OK", "", &big, false)).await;
        let err = ReqwestJwksFetcher::new().fetch(&url).await.unwrap_err();
        assert!(err.0.contains("bytes"), "{err}");
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let (target, target_hits) = serve(http("200 OK", "", br#"{"keys":[]}"#, true)).await;
        let (url, _) = serve(http("302 Found", &format!("Location: {target}\r\n"), b"", true)).await;
        let err = ReqwestJwksFetcher::new().fetch(&url).await.unwrap_err();
        assert!(err.0.contains("302"), "{err}");
        assert_eq!(target_hits.load(std::sync::atomic::Ordering::SeqCst), 0, "the redirect target was fetched");
    }
}
