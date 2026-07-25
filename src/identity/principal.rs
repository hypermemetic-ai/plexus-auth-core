//! [`Principal`] — an issuer-namespaced subject.
//!
//! This is the **subject-name** half of the two-`Principal` split documented
//! in [`crate::identity`]. It answers *which* identity, and *who vouches for
//! it*; [`crate::principal::Principal`] answers *what kind of actor* is on
//! the other end of the call.
//!
//! # Relationship to `plexus_core::identity::Principal`
//!
//! PLX-75 landed a type of the same name, same string grammar, and same wire
//! form in `plexus-core`. This one is a deliberate **mirror**, not a fork:
//! `plexus-core` depends on `plexus-auth-core`, so the dependency arrow makes
//! it impossible for `AuthContext` (which lives here) to name the plexus-core
//! type. The grammar is pinned identical on purpose so that
//! `plexus_core::identity::Principal` can be collapsed into a re-export of
//! this type in a follow-up with no wire, no storage, and no API change.
//! `plexus-idp/tests/principal_equivalence.rs` mechanically asserts the two
//! agree on every accepted and rejected form.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The separator between issuer and subject in a principal's string form.
const SEP: char = ':';

/// Who vouches for a [`Principal`]'s subject.
///
/// The set is deliberately **open for extension but closed for guessing**:
///
/// - `#[non_exhaustive]` lets a later build add an authenticator (NIP-05,
///   WebAuthn, mTLS, …) without it being a breaking change for downstream
///   `match` arms; but
/// - [`Issuer::parse`] has an explicit arm per known issuer and *rejects*
///   anything else. An unknown prefix is a [`PrincipalParseError::UnknownIssuer`],
///   never a silently-accepted opaque string. Adding an issuer therefore
///   requires adding its validation rule in the same commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Issuer {
    /// plexus-idp: a server-minted UUID v4 (`plexus-idp/src/core.rs`).
    Idp,
    /// A self-sovereign nostr identity: a 32-byte secp256k1 x-only pubkey.
    Nostr,
    /// A machine credential minted as an API key.
    ApiKey,
}

impl Issuer {
    /// The issuer's wire prefix.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idp => "idp",
            Self::Nostr => "nostr",
            Self::ApiKey => "apikey",
        }
    }

    /// Parse an issuer prefix. Unknown prefixes are an error, not a new issuer.
    pub fn parse(s: &str) -> Result<Self, PrincipalParseError> {
        match s {
            "idp" => Ok(Self::Idp),
            "nostr" => Ok(Self::Nostr),
            "apikey" => Ok(Self::ApiKey),
            other => Err(PrincipalParseError::UnknownIssuer(other.to_string())),
        }
    }

    /// Validate a subject against this issuer's rules.
    fn validate(self, subject: &str) -> Result<(), PrincipalParseError> {
        if subject.is_empty() {
            return Err(PrincipalParseError::EmptySubject(self));
        }
        if subject.contains(SEP) {
            return Err(PrincipalParseError::SubjectContainsSeparator(self));
        }

        match self {
            // A canonical lowercase hyphenated UUID, exactly as idp mints it
            // (`Uuid::new_v4().to_string()`). Braced/URN/simple forms are
            // rejected so that one identity has exactly one rendering and
            // `Display`/`FromStr` round-trip byte-for-byte.
            Self::Idp => {
                let parsed = uuid::Uuid::parse_str(subject)
                    .map_err(|_| PrincipalParseError::InvalidUuid(subject.to_string()))?;
                if parsed.hyphenated().to_string() != subject {
                    return Err(PrincipalParseError::InvalidUuid(subject.to_string()));
                }
                Ok(())
            }

            // 64 lowercase hex characters — the x-only pubkey encoding every
            // nostr implementation uses. Uppercase is rejected rather than
            // normalized: normalizing would break the exact round-trip and
            // give one key two principals.
            Self::Nostr => {
                if subject.len() != 64 {
                    return Err(PrincipalParseError::InvalidNostrPubkey {
                        subject: subject.to_string(),
                        reason: "expected exactly 64 hex characters",
                    });
                }
                if !subject
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(PrincipalParseError::InvalidNostrPubkey {
                        subject: subject.to_string(),
                        reason: "expected lowercase hex only",
                    });
                }
                Ok(())
            }

            // An opaque key id. Constrained to printable, non-whitespace ASCII
            // so a principal is always safely renderable in a log line, a URL
            // segment, or a header value.
            Self::ApiKey => {
                if subject
                    .bytes()
                    .any(|b| !b.is_ascii_graphic() || b == b'"' || b == b'\\')
                {
                    return Err(PrincipalParseError::InvalidApiKeyId(subject.to_string()));
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a string is not a valid [`Principal`].
///
/// Intentionally **not** `#[non_exhaustive]`, mirroring
/// `plexus_core::identity::PrincipalParseError` exactly so that collapsing
/// that type into a re-export of this one is a no-op for downstream `match`
/// arms. The `Display` strings are pinned identical for the same reason and
/// are asserted equal by `plexus-idp/tests/principal_equivalence.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalParseError {
    /// No `:` separator at all.
    MissingSeparator(String),

    /// The prefix is not a known issuer.
    UnknownIssuer(String),

    /// The subject was empty.
    EmptySubject(Issuer),

    /// The subject contained a second `:`, making the rendering ambiguous.
    SubjectContainsSeparator(Issuer),

    /// `idp:` subject was not a canonical hyphenated UUID.
    InvalidUuid(String),

    /// `nostr:` subject was not a 64-character lowercase hex pubkey.
    InvalidNostrPubkey {
        /// The rejected subject.
        subject: String,
        /// Which rule it broke.
        reason: &'static str,
    },

    /// `apikey:` subject contained non-printable or quoting characters.
    InvalidApiKeyId(String),
}

impl fmt::Display for PrincipalParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSeparator(s) => write!(
                f,
                "principal `{s}` has no `{SEP}` separator; expected `<issuer>{SEP}<subject>`"
            ),
            Self::UnknownIssuer(s) => write!(
                f,
                "unknown principal issuer `{s}`; known issuers: idp, nostr, apikey"
            ),
            Self::EmptySubject(i) => write!(f, "principal issuer `{i}` has an empty subject"),
            Self::SubjectContainsSeparator(i) => write!(
                f,
                "principal subject for issuer `{i}` contains a `{SEP}`, which is ambiguous"
            ),
            Self::InvalidUuid(s) => {
                write!(f, "principal subject `{s}` is not a canonical hyphenated UUID")
            }
            Self::InvalidNostrPubkey { subject, reason } => write!(
                f,
                "principal subject `{subject}` is not a valid nostr pubkey: {reason}"
            ),
            Self::InvalidApiKeyId(s) => {
                write!(f, "principal subject `{s}` is not a valid api key id")
            }
        }
    }
}

impl std::error::Error for PrincipalParseError {}

/// An issuer-namespaced subject: `idp:<uuid>`, `nostr:<64-hex>`, `apikey:<id>`.
///
/// # Invariants
///
/// The fields are private and both constructors ([`Principal::new`] and
/// [`FromStr`]) validate, so *every* `Principal` value in existence satisfies
/// its issuer's rules. `Deserialize` goes through `FromStr`, so a JSON document
/// cannot smuggle in an invalid one either.
///
/// [`Display`](fmt::Display) and [`FromStr`] round-trip **exactly** — no
/// normalization is performed anywhere, because normalizing would let one
/// subject have two renderings and therefore two unequal `Principal`s.
///
/// # Wire form
///
/// A plain JSON string (`"idp:6ba7b810-9dad-11d1-80b4-00c04fd430c8"`), not an
/// object — implemented by hand rather than with `#[serde(transparent)]` so
/// that deserialization can enforce validation.
///
/// # This is a name, not a proof
///
/// Holding a `Principal` proves nothing about authentication: it is data,
/// parsed from a string. The *proof* is [`Authenticated`](super::Authenticated),
/// which only an [`Authenticator`](super::Authenticator) produces, and whose
/// principal field was populated from verified material.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal {
    issuer: Issuer,
    subject: String,
}

impl Principal {
    /// Build a principal, validating the subject against the issuer's rules.
    ///
    /// # Errors
    ///
    /// See [`PrincipalParseError`].
    pub fn new(issuer: Issuer, subject: impl Into<String>) -> Result<Self, PrincipalParseError> {
        let subject = subject.into();
        issuer.validate(&subject)?;
        Ok(Self { issuer, subject })
    }

    /// An idp-minted principal from a UUID.
    pub fn idp(uuid: &uuid::Uuid) -> Self {
        // A `Uuid` always renders as a canonical hyphenated string, so this
        // cannot fail — but it still goes through the validating constructor
        // so there is exactly one path that builds a `Principal`.
        Self::new(Issuer::Idp, uuid.hyphenated().to_string())
            .expect("a canonical Uuid is always a valid idp subject")
    }

    /// Interpret a legacy bare `user_id` as an idp principal.
    ///
    /// This is the bridge that makes [`AuthContext::principal`] and
    /// [`AuthContext::user_id`] agree by construction: today's `user_id` is
    /// a plexus-idp-minted UUID v4 reused verbatim as the JWT `sub`, so
    /// `idp:<user_id>` is the same identity under a namespaced name.
    ///
    /// Returns `None` for anything that is not a canonical hyphenated UUID —
    /// notably `"anonymous"`, and any `user_id` minted by a system that is
    /// not plexus-idp. A `None` here means "this context has no principal we
    /// can name", never "this context is authenticated as something else".
    ///
    /// [`AuthContext::principal`]: crate::AuthContext::principal
    /// [`AuthContext::user_id`]: crate::AuthContext#structfield.user_id
    pub fn from_legacy_user_id(user_id: &str) -> Option<Self> {
        Self::new(Issuer::Idp, user_id).ok()
    }

    /// Who vouches for this subject.
    pub fn issuer(&self) -> Issuer {
        self.issuer
    }

    /// The issuer-scoped subject, without the prefix.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The value this principal contributes to the legacy
    /// [`AuthContext::user_id`](crate::AuthContext#structfield.user_id)
    /// field.
    ///
    /// For `idp:` principals this is the bare subject — byte-identical to
    /// what plexus-idp writes today, so nothing that reads `user_id`
    /// observes any change. For every other issuer it is the **full**
    /// namespaced string (`nostr:abc…`), because a nostr pubkey and an idp
    /// UUID share no namespace and must never collide in a column that
    /// callers treat as a unique user key.
    pub fn as_legacy_user_id(&self) -> String {
        match self.issuer {
            Issuer::Idp => self.subject.clone(),
            _ => self.to_string(),
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", self.issuer.as_str(), SEP, self.subject)
    }
}

impl FromStr for Principal {
    type Err = PrincipalParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split on the FIRST separator; `Issuer::validate` then rejects any
        // further `:` in the remainder, so `idp:a:b` is an error rather than a
        // principal with a colon-bearing subject.
        let (prefix, subject) = s
            .split_once(SEP)
            .ok_or_else(|| PrincipalParseError::MissingSeparator(s.to_string()))?;
        let issuer = Issuer::parse(prefix)?;
        issuer.validate(subject)?;
        Ok(Self {
            issuer,
            subject: subject.to_string(),
        })
    }
}

impl Serialize for Principal {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const PUBKEY: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    fn samples() -> Vec<&'static str> {
        vec![
            "idp:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "nostr:3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
            "apikey:ak_live_01HQ8ZQK",
        ]
    }

    #[test]
    fn display_fromstr_round_trip_exactly() {
        for s in samples() {
            let p: Principal = s.parse().expect(s);
            assert_eq!(p.to_string(), s);
            let again: Principal = p.to_string().parse().unwrap();
            assert_eq!(p, again);
        }
    }

    #[test]
    fn serde_round_trips_as_a_plain_string() {
        for s in samples() {
            let p: Principal = s.parse().unwrap();
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{s}\""));
            let back: Principal = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn deserialization_enforces_validation() {
        assert!(serde_json::from_str::<Principal>("\"ldap:someone\"").is_err());
        assert!(serde_json::from_str::<Principal>("\"nostr:NOTHEX\"").is_err());
    }

    #[test]
    fn rejects_unknown_issuer_and_missing_separator() {
        assert!(matches!(
            "ldap:someone".parse::<Principal>(),
            Err(PrincipalParseError::UnknownIssuer(i)) if i == "ldap"
        ));
        assert!(matches!(
            "idp".parse::<Principal>(),
            Err(PrincipalParseError::MissingSeparator(_))
        ));
    }

    #[test]
    fn rejects_malformed_subjects_per_issuer() {
        assert!(format!("idp:{}", "not-a-uuid").parse::<Principal>().is_err());
        assert!(format!("nostr:{}", PUBKEY.to_uppercase())
            .parse::<Principal>()
            .is_err());
        assert!("apikey:ak live".parse::<Principal>().is_err());
        assert!("idp:".parse::<Principal>().is_err());
        assert!(format!("idp:{UUID}:extra").parse::<Principal>().is_err());
    }

    #[test]
    fn from_legacy_user_id_round_trips_todays_user_ids() {
        let p = Principal::from_legacy_user_id(UUID).unwrap();
        assert_eq!(p.to_string(), format!("idp:{UUID}"));
        assert_eq!(p.as_legacy_user_id(), UUID);
        // The anonymous sentinel is not a principal.
        assert!(Principal::from_legacy_user_id("anonymous").is_none());
    }

    #[test]
    fn non_idp_principals_keep_their_namespace_in_the_legacy_field() {
        let p: Principal = format!("nostr:{PUBKEY}").parse().unwrap();
        assert_eq!(p.as_legacy_user_id(), format!("nostr:{PUBKEY}"));
        // and that string is not mistakable for an idp user_id
        assert!(Principal::from_legacy_user_id(&p.as_legacy_user_id()).is_none());
    }

    #[test]
    fn principals_from_different_issuers_never_collide() {
        let a = Principal::new(Issuer::ApiKey, UUID).unwrap();
        let b = Principal::new(Issuer::Idp, UUID).unwrap();
        assert_ne!(a, b);
        assert_ne!(a.to_string(), b.to_string());
    }

    #[test]
    fn idp_helper_matches_manual_construction() {
        let u = uuid::Uuid::parse_str(UUID).unwrap();
        assert_eq!(Principal::idp(&u), Principal::new(Issuer::Idp, UUID).unwrap());
    }
}
