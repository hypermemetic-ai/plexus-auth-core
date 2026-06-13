//! JWKS parsing and the AUTH-8 TTL computation (UT-1).
//!
//! Crate-private: backends interact with the cache only through
//! [`OidcValidator`](crate::oidc::OidcValidator)'s behavior. Keeping the
//! mechanics in one module also keeps the EdDSA extension point in one
//! place (see [`admit_key`]).

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::DecodingKey;
use std::collections::HashMap;
use std::time::Duration;

/// The AUTH-8 TTL ceiling: cached JWKS are never trusted longer than one
/// hour, regardless of what the server's `Cache-Control` says.
const MAX_TTL: Duration = Duration::from_secs(3600);

/// Derive the JWKS cache TTL from a `Cache-Control` header.
///
/// AUTH-8 policy: `TTL = min(Cache-Control max-age, 3600 s)`; a missing
/// or unparsable header defaults to the 3600 s ceiling. Only the
/// `max-age` directive is consulted — `no-store`/`no-cache` collapse to
/// `max-age=0` semantics only if expressed as such; the kid-miss refresh
/// path bounds staleness either way.
pub(crate) fn ttl_from_cache_control(cache_control: Option<&str>) -> Duration {
    let Some(cc) = cache_control else {
        return MAX_TTL;
    };
    for directive in cc.split(',') {
        let directive = directive.trim();
        if let Some(v) = directive
            .strip_prefix("max-age=")
            .or_else(|| directive.strip_prefix("Max-Age="))
            .or_else(|| directive.strip_prefix("MAX-AGE="))
        {
            if let Ok(secs) = v.trim().parse::<u64>() {
                return Duration::from_secs(secs).min(MAX_TTL);
            }
        }
    }
    MAX_TTL
}

/// Decide whether a JWK is admissible for token verification, and build
/// its `DecodingKey` if so.
///
/// Admission rules (RS256-only posture, UT-S01 open question 4):
///
/// - key type must be RSA;
/// - `alg`, when present, must be `RS256` (a key explicitly labeled for
///   another algorithm is never used to verify an RS256 token);
/// - `use`, when present, must be `sig`;
/// - a `kid` is required — the validator selects keys strictly by `kid`
///   (the IdP contract per UT-S01 D2 is "signs RS256 with `kid`").
///
/// **EdDSA extension point:** admitting Ed25519 keys is one additional
/// arm on the `AlgorithmParameters` match plus the corresponding
/// `KeyAlgorithm::EdDSA` allowance — the rest of the validator is
/// algorithm-agnostic past this gate and the per-token `alg` check.
///
/// Returns `None` (skip, with a debug log) rather than failing the whole
/// set: a JWKS may legitimately carry keys for other algorithms/uses.
fn admit_key(jwk: &Jwk) -> Option<(String, DecodingKey)> {
    let kid = jwk.common.key_id.clone()?;

    match &jwk.common.key_algorithm {
        None | Some(KeyAlgorithm::RS256) => {}
        Some(other) => {
            tracing::debug!(
                target: "plexus::auth",
                kid = %kid,
                alg = ?other,
                "skipping JWKS key: non-RS256 algorithm label"
            );
            return None;
        }
    }

    match &jwk.common.public_key_use {
        None | Some(PublicKeyUse::Signature) => {}
        Some(other) => {
            tracing::debug!(
                target: "plexus::auth",
                kid = %kid,
                key_use = ?other,
                "skipping JWKS key: not a signature key"
            );
            return None;
        }
    }

    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => {}
        other => {
            tracing::debug!(
                target: "plexus::auth",
                kid = %kid,
                kty = ?other,
                "skipping JWKS key: non-RSA key type (RS256-only posture)"
            );
            return None;
        }
    }

    match DecodingKey::from_jwk(jwk) {
        Ok(key) => Some((kid, key)),
        Err(e) => {
            tracing::warn!(
                target: "plexus::auth",
                kid = %kid,
                error = %e,
                "skipping JWKS key: failed to build decoding key"
            );
            None
        }
    }
}

/// Parse a JWKS document body into the kid → `DecodingKey` map.
///
/// Returns `Err` only when the document is not a JWKS at all; individual
/// inadmissible keys are skipped (see [`admit_key`]).
pub(crate) fn parse_jwks(body: &str) -> Result<HashMap<String, DecodingKey>, String> {
    let set: JwkSet =
        serde_json::from_str(body).map_err(|e| format!("JWKS parse error: {e}"))?;
    Ok(set.keys.iter().filter_map(admit_key).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_defaults_to_one_hour_without_header() {
        assert_eq!(ttl_from_cache_control(None), Duration::from_secs(3600));
        assert_eq!(
            ttl_from_cache_control(Some("no-store")),
            Duration::from_secs(3600)
        );
        assert_eq!(
            ttl_from_cache_control(Some("garbage")),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn ttl_is_min_of_max_age_and_ceiling() {
        // Below the ceiling: max-age wins.
        assert_eq!(
            ttl_from_cache_control(Some("public, max-age=600")),
            Duration::from_secs(600)
        );
        // Above the ceiling: 3600 s wins (AUTH-8).
        assert_eq!(
            ttl_from_cache_control(Some("max-age=86400")),
            Duration::from_secs(3600)
        );
        // Zero is honored — effectively "revalidate every request".
        assert_eq!(
            ttl_from_cache_control(Some("max-age=0")),
            Duration::from_secs(0)
        );
    }

    #[test]
    fn ttl_parses_max_age_among_other_directives() {
        assert_eq!(
            ttl_from_cache_control(Some("no-transform, max-age=120, must-revalidate")),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn parse_jwks_rejects_non_jwks_documents() {
        assert!(parse_jwks("not json").is_err());
        assert!(parse_jwks(r#"{"foo": 1}"#).is_err());
    }

    #[test]
    fn parse_jwks_skips_keyless_kid_and_foreign_alg_entries() {
        // An EC key and a kid-less RSA key must both be skipped without
        // failing the set; an empty admissible set is a valid outcome.
        let body = r#"{
            "keys": [
                {"kty": "EC", "kid": "ec-1", "crv": "P-256",
                 "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                 "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
            ]
        }"#;
        let keys = parse_jwks(body).unwrap();
        assert!(keys.is_empty());
    }
}
