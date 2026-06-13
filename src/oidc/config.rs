//! Validator configuration: trusted issuer + expected audience (UT-1).

use crate::capabilities::IssuerUrl;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Why an `Audience::try_new` rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudienceError {
    /// Empty, longer than 256 bytes, or contains non-printable bytes.
    InvalidShape(String),
}

impl fmt::Display for AudienceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidShape(s) => {
                write!(f, "invalid audience {s:?}: must be non-empty printable ASCII, ≤ 256 bytes")
            }
        }
    }
}

impl std::error::Error for AudienceError {}

/// An OAuth2 / OIDC audience (`aud`) value.
///
/// Per UT-S01 D1, the audience is **per-backend** (Auth0 "API identifier"
/// convention, e.g. `plexus:trak`) so a token minted for one backend
/// cannot be replayed against another. A deployment that wants one shared
/// audience configures it explicitly — that is an opt-down, not the
/// default.
///
/// Validated newtype in the style of the capability-advertisement types
/// (`ClientId`, `CookieName`, ...): public `try_new`, transparent serde,
/// `JsonSchema` for IR/codegen integration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Audience(String);

impl Audience {
    /// Construct an `Audience`. Rules: non-empty, ≤ 256 bytes, printable
    /// ASCII (no control bytes, no DEL) — the same shape rules as tenant
    /// identifiers, for the same reason (safe in logs, binds, filenames).
    pub fn try_new(s: impl Into<String>) -> Result<Self, AudienceError> {
        let s = s.into();
        let ok = !s.is_empty() && s.len() <= 256 && !s.bytes().any(|b| b < 0x20 || b == 0x7f);
        if !ok {
            return Err(AudienceError::InvalidShape(s));
        }
        Ok(Self(s))
    }

    /// Borrow the inner value as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration for an [`OidcValidator`](crate::oidc::OidcValidator).
///
/// Names the single trusted issuer and the audience this backend expects
/// in every token. Multi-issuer federation is deliberately out of scope
/// (UT-S01 open question 3 — a product decision); the validator type
/// composes trivially into a set if that lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OidcConfig {
    issuer: IssuerUrl,
    audience: Audience,
}

impl OidcConfig {
    /// Build a config from a validated issuer and audience.
    pub fn new(issuer: IssuerUrl, audience: Audience) -> Self {
        Self { issuer, audience }
    }

    /// The trusted issuer URL.
    pub fn issuer(&self) -> &IssuerUrl {
        &self.issuer
    }

    /// The audience this backend expects in `aud`.
    pub fn audience(&self) -> &Audience {
        &self.audience
    }

    /// The OIDC Discovery URL for the configured issuer:
    /// `{issuer}/.well-known/openid-configuration` (issuer trailing slash
    /// normalized away first, per OIDC Discovery §4).
    pub fn discovery_url(&self) -> url::Url {
        let base = self.issuer.as_url().as_str().trim_end_matches('/').to_string();
        url::Url::parse(&format!("{base}/.well-known/openid-configuration"))
            .expect("issuer URL + well-known suffix is always a valid URL")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer(s: &str) -> IssuerUrl {
        IssuerUrl::try_new(s.parse().unwrap()).unwrap()
    }

    #[test]
    fn audience_accepts_api_identifier_shapes() {
        Audience::try_new("plexus:trak").unwrap();
        Audience::try_new("https://api.example.com").unwrap();
        Audience::try_new("my-api").unwrap();
    }

    #[test]
    fn audience_rejects_bad_shapes() {
        assert!(Audience::try_new("").is_err());
        assert!(Audience::try_new("a".repeat(257)).is_err());
        assert!(Audience::try_new("evil\0aud").is_err());
    }

    #[test]
    fn discovery_url_normalizes_trailing_slash() {
        // `Url` normalizes a host-only URL to a trailing slash; the
        // discovery path must not end up with a double slash.
        let c = OidcConfig::new(
            issuer("https://idp.example.com"),
            Audience::try_new("plexus:trak").unwrap(),
        );
        assert_eq!(
            c.discovery_url().as_str(),
            "https://idp.example.com/.well-known/openid-configuration"
        );

        let c2 = OidcConfig::new(
            issuer("https://idp.example.com/tenant/"),
            Audience::try_new("plexus:trak").unwrap(),
        );
        assert_eq!(
            c2.discovery_url().as_str(),
            "https://idp.example.com/tenant/.well-known/openid-configuration"
        );
    }

    #[test]
    fn config_round_trips_serde() {
        let c = OidcConfig::new(
            issuer("https://idp.example.com"),
            Audience::try_new("plexus:trak").unwrap(),
        );
        let s = serde_json::to_string(&c).unwrap();
        let back: OidcConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);
    }
}
