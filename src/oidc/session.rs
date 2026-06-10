//! `OidcSessionValidator` — the framework [`SessionValidator`] over the
//! OIDC validator (UT-1, UT-S01 D4 step 3).
//!
//! This is the type a backend registers at its WS-upgrade perimeter to
//! replace a bespoke JWT path (e.g. trak's `TrakAuth::try_jwt`, the
//! HS256 shared-secret path that issue 74103adf indicts). Fallback
//! mechanisms that sit *beside* the OIDC surface (API keys, SRP) stay in
//! the backend's own `SessionValidator` chain, per the UT-S01
//! interchangeability bar.

use async_trait::async_trait;

use crate::auth::{AuthContext, SessionValidator};
use crate::capabilities::CookieName;
use crate::oidc::validator::OidcValidator;

/// Default cookie carrying the access token — the convention shared with
/// synapse's `_self` store and WS-upgrade cookie attach (`access_token=`).
const DEFAULT_COOKIE: &str = "access_token";

/// A [`SessionValidator`] that accepts RS256 OIDC tokens.
///
/// Extracts the token from the configured cookie in the upgrade request's
/// Cookie header (or treats the input as a bare token when it contains no
/// `=`, matching the trak reference's tolerance for raw `-t <jwt>`
/// invocations), validates it via [`OidcValidator`], and converts the
/// result into an [`AuthContext`] (see
/// [`VerifiedToken::into_auth_context`](crate::oidc::VerifiedToken::into_auth_context)).
///
/// Per the `SessionValidator` contract, every rejection maps to `None`
/// (the connection proceeds as anonymous); the precise [`OidcError`]
/// (crate::oidc::OidcError) is logged at debug level under
/// `target = "plexus::auth"` — never surfaced to the wire.
pub struct OidcSessionValidator {
    validator: OidcValidator,
    cookie: CookieName,
}

impl OidcSessionValidator {
    /// Wrap a validator; tokens are read from the `access_token` cookie.
    pub fn new(validator: OidcValidator) -> Self {
        Self {
            validator,
            cookie: CookieName::try_new(DEFAULT_COOKIE)
                .expect("the literal \"access_token\" is a valid cookie name"),
        }
    }

    /// Wrap a validator reading a custom cookie.
    pub fn with_cookie(validator: OidcValidator, cookie: CookieName) -> Self {
        Self { validator, cookie }
    }

    /// The wrapped validator (e.g. for direct `validate_token` calls on
    /// non-cookie paths).
    pub fn validator(&self) -> &OidcValidator {
        &self.validator
    }
}

/// Parse a Cookie header for the named cookie's value, or return the raw
/// string when it looks like a bare token (no `=`). Extracted verbatim
/// from the trak reference (`plexus-trak/src/auth.rs`,
/// `extract_token_from_cookies`), parameterized by cookie name.
fn extract_token<'a>(cookie_header: &'a str, cookie_name: &str) -> &'a str {
    if !cookie_header.contains('=') {
        return cookie_header.trim();
    }
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(cookie_name) {
            if let Some(val) = rest.strip_prefix('=') {
                return val.trim();
            }
        }
    }
    cookie_header.trim()
}

#[async_trait]
impl SessionValidator for OidcSessionValidator {
    async fn validate(&self, cookie_value: &str) -> Option<AuthContext> {
        let token = extract_token(cookie_value, self.cookie.as_str());
        match self.validator.validate_token(token).await {
            Ok(verified) => Some(verified.into_auth_context()),
            Err(e) => {
                tracing::debug!(
                    target: "plexus::auth",
                    error = %e,
                    "OIDC session validation rejected token"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_named_cookie_from_header() {
        assert_eq!(
            extract_token("access_token=eyJx; other=1", "access_token"),
            "eyJx"
        );
        assert_eq!(
            extract_token("first=0; access_token=eyJx", "access_token"),
            "eyJx"
        );
    }

    #[test]
    fn bare_token_passes_through() {
        assert_eq!(extract_token("  eyJhbGciOi  ", "access_token"), "eyJhbGciOi");
    }

    #[test]
    fn custom_cookie_name_is_honored() {
        assert_eq!(extract_token("session=abc; access_token=no", "session"), "abc");
    }

    #[test]
    fn prefix_cookie_names_do_not_match() {
        // `access_token_v2` must not satisfy a lookup for `access_token`.
        assert_eq!(
            extract_token("access_token_v2=evil; access_token=good", "access_token"),
            "good"
        );
    }
}
