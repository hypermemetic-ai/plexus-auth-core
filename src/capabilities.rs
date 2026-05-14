//! Capability advertisement primitives — what a backend tells a client about
//! its authentication surface, served at `_info`.
//!
//! Per AUTHZ-S01-output §2: a backend extends its `_info` response with an
//! optional `auth_capabilities` field carrying a [`BackendAuthCapabilities`].
//! Clients (synapse CLI, gamma, generated SDKs, agents) read it to decide
//! which authentication flow to drive.
//!
//! These types are *not* sealed — the cryptographic anchor is `AuthContext` /
//! `VerifiedUser` in this same crate. Capability-advertisement types carry
//! contract metadata; they belong here with the auth primitives so the
//! dependency graph and the orphan-rule defense extend uniformly per AUTHZ-0
//! §"Crate-level isolation amplifies the seal".
//!
//! Each newtype follows the strong-typing skill: `Debug, Clone, PartialEq, Eq,
//! Hash, Serialize, Deserialize`; `#[serde(transparent)]` for single-field
//! wrappers; validation at the wire boundary via a `try_new` constructor;
//! `as_str()` accessor; `Display` for tracing.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use url::Url;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Why a `MethodPath::try_new` rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodPathError {
    /// Empty input.
    Empty,
    /// Path does not match `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`.
    InvalidFormat(String),
}

impl fmt::Display for MethodPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "method path is empty"),
            Self::InvalidFormat(s) => write!(
                f,
                "method path {:?} does not match `^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$`",
                s
            ),
        }
    }
}

impl std::error::Error for MethodPathError {}

/// Why an `IssuerUrl::try_new` rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerUrlError {
    /// Scheme is not `https`, and host is not localhost on `http`.
    InsecureScheme(String),
}

impl fmt::Display for IssuerUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecureScheme(u) => write!(
                f,
                "issuer URL {:?} must be https:// (or http://localhost)",
                u
            ),
        }
    }
}

impl std::error::Error for IssuerUrlError {}

/// Why a `CookieName::try_new` rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieNameError {
    /// Empty.
    Empty,
    /// Contains a byte outside RFC 6265's `cookie-name = token` set.
    InvalidToken(String),
}

impl fmt::Display for CookieNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "cookie name is empty"),
            Self::InvalidToken(s) => write!(
                f,
                "cookie name {:?} contains characters outside RFC 6265 token set",
                s
            ),
        }
    }
}

impl std::error::Error for CookieNameError {}

/// Why a `HeaderName::try_new` rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderNameError {
    /// Empty.
    Empty,
    /// Contains a byte outside RFC 7230's `field-name = token` set.
    InvalidToken(String),
}

impl fmt::Display for HeaderNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "header name is empty"),
            Self::InvalidToken(s) => write!(
                f,
                "header name {:?} contains characters outside RFC 7230 token set",
                s
            ),
        }
    }
}

impl std::error::Error for HeaderNameError {}

/// Why a `ClientId::try_new` rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientIdError {
    /// Empty.
    Empty,
}

impl fmt::Display for ClientIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "client_id is empty"),
        }
    }
}

impl std::error::Error for ClientIdError {}

/// Why a `BackendAuthCapabilities::new` rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendAuthCapabilitiesError {
    /// `default` index is out of range for `mechanisms`.
    DefaultOutOfRange { default: usize, len: usize },
}

impl fmt::Display for BackendAuthCapabilitiesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultOutOfRange { default, len } => write!(
                f,
                "default index {} is out of range for mechanisms (len = {})",
                default, len
            ),
        }
    }
}

impl std::error::Error for BackendAuthCapabilitiesError {}

// ---------------------------------------------------------------------------
// MethodPath
// ---------------------------------------------------------------------------

/// A dotted method path like `auth.login` or `cone.send_message`.
///
/// Wire form: bare string. Validation: must match
/// `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`. At least two segments are required
/// (the activation namespace plus the method name).
///
/// Wildcards are NOT allowed — wildcards belong to `Scope` (AUTHZ-CORE-4).
///
/// Per AUTHZ-S01-output §1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct MethodPath(String);

impl MethodPath {
    /// Construct a `MethodPath`, validating the dotted-path grammar.
    pub fn try_new(s: impl Into<String>) -> Result<Self, MethodPathError> {
        let s = s.into();
        if s.is_empty() {
            return Err(MethodPathError::Empty);
        }
        if !is_valid_method_path(&s) {
            return Err(MethodPathError::InvalidFormat(s));
        }
        Ok(Self(s))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first segment — the activation namespace (e.g., `"auth"` in
    /// `"auth.login"`).
    pub fn activation(&self) -> &str {
        self.0.split('.').next().expect("validated: at least one segment")
    }

    /// The last segment — the method name (e.g., `"login"` in
    /// `"auth.login"`).
    pub fn method(&self) -> &str {
        self.0.rsplit('.').next().expect("validated: at least one segment")
    }
}

impl fmt::Display for MethodPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_valid_method_path(s: &str) -> bool {
    // Grammar: `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`
    // Implemented without `regex` to avoid pulling that dep into auth-core.
    let mut segments = s.split('.');
    let first = match segments.next() {
        Some(seg) => seg,
        None => return false,
    };
    if !is_valid_path_segment(first) {
        return false;
    }
    let mut has_second_segment = false;
    for seg in segments {
        has_second_segment = true;
        if !is_valid_path_segment(seg) {
            return false;
        }
    }
    has_second_segment
}

fn is_valid_path_segment(seg: &str) -> bool {
    let mut chars = seg.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false, // empty segment
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// IssuerUrl
// ---------------------------------------------------------------------------

/// An OIDC-style issuer URL.
///
/// Constructor validates `https://` URLs and `http://localhost[:port]/` URLs
/// (loopback exception for development). All other schemes / hosts are
/// rejected.
///
/// Per AUTHZ-S01-output §1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct IssuerUrl(#[schemars(with = "String")] Url);

impl IssuerUrl {
    /// Construct an `IssuerUrl`. Accepts `https://...` and `http://localhost...`.
    pub fn try_new(u: Url) -> Result<Self, IssuerUrlError> {
        let scheme = u.scheme();
        let is_https = scheme == "https";
        let is_localhost_http = scheme == "http"
            && u
                .host_str()
                .map(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]")
                .unwrap_or(false);
        if !(is_https || is_localhost_http) {
            return Err(IssuerUrlError::InsecureScheme(u.to_string()));
        }
        Ok(Self(u))
    }

    /// Borrow the inner URL.
    pub fn as_url(&self) -> &Url {
        &self.0
    }
}

impl fmt::Display for IssuerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl std::hash::Hash for IssuerUrl {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

// ---------------------------------------------------------------------------
// ClientId
// ---------------------------------------------------------------------------

/// OIDC `client_id` opaque identifier.
///
/// Treated as bytes; only non-empty is enforced. Per AUTHZ-S01-output §1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct ClientId(String);

impl ClientId {
    /// Construct a `ClientId`. Rejects only the empty string.
    pub fn try_new(s: impl Into<String>) -> Result<Self, ClientIdError> {
        let s = s.into();
        if s.is_empty() {
            return Err(ClientIdError::Empty);
        }
        Ok(Self(s))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// CookieName
// ---------------------------------------------------------------------------

/// A cookie name (e.g. `"plexus_session"`). RFC 6265 token-set validation.
///
/// Per AUTHZ-S01-output §1. RFC 6265 defines `cookie-name = token` and `token`
/// from RFC 7230 §3.2.6: any VCHAR except CTLs, separators, and the
/// delimiters listed in RFC 7230.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct CookieName(String);

impl CookieName {
    /// Construct a `CookieName`, validating against RFC 6265 / 7230 `token`.
    pub fn try_new(s: impl Into<String>) -> Result<Self, CookieNameError> {
        let s = s.into();
        if s.is_empty() {
            return Err(CookieNameError::Empty);
        }
        if !s.bytes().all(is_rfc7230_token_byte) {
            return Err(CookieNameError::InvalidToken(s));
        }
        Ok(Self(s))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CookieName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// RFC 7230 §3.2.6 token character set.
///
/// `token = 1*tchar`,
/// `tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^"
///           / "_" / "`" / "|" / "~" / DIGIT / ALPHA`
fn is_rfc7230_token_byte(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

// ---------------------------------------------------------------------------
// HeaderName
// ---------------------------------------------------------------------------

/// An HTTP header name (e.g. `"Authorization"`).
///
/// Stored normalized to lowercase so equality matches the case-insensitive
/// HTTP convention. RFC 7230 §3.2 token-set validation applied to the input
/// before normalization. Per AUTHZ-S01-output §1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct HeaderName(String);

impl HeaderName {
    /// Construct a `HeaderName`. The input is lowercased on construction;
    /// invalid token characters are rejected.
    pub fn try_new(s: impl Into<String>) -> Result<Self, HeaderNameError> {
        let s = s.into();
        if s.is_empty() {
            return Err(HeaderNameError::Empty);
        }
        if !s.bytes().all(is_rfc7230_token_byte) {
            return Err(HeaderNameError::InvalidToken(s));
        }
        Ok(Self(s.to_ascii_lowercase()))
    }

    /// Borrow the inner (normalized, lowercase) string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// AuthMechanism
// ---------------------------------------------------------------------------

/// Tagged union of supported auth mechanisms a backend advertises.
///
/// Wire form: discriminated on `kind`, snake_case (`"bearer"`, `"cookie"`,
/// `"oidc"`, `"anonymous"`). See AUTHZ-S01-output §2 for canonical JSON
/// examples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthMechanism {
    /// Static bearer token (today's substrate `--api-key` shape). Not
    /// user-bound; the token authorizes the bearer.
    Bearer {
        /// Header carrying the token, e.g. `Authorization`.
        header: HeaderName,
    },

    /// Cookie session, with a backend-defined `login` method that issues
    /// `Set-Cookie`.
    Cookie {
        /// Name of the session cookie.
        cookie: CookieName,
        /// Method the client calls to issue/establish the cookie.
        login: MethodPath,
        /// Optional method to renew the cookie.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        refresh: Option<MethodPath>,
        /// Optional method to invalidate the cookie.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        logout: Option<MethodPath>,
    },

    /// OIDC mechanism (designed-for; may not be implemented in initial epic).
    Oidc {
        /// Issuer URL of the IdP.
        issuer: IssuerUrl,
        /// `client_id` registered with the IdP for this backend.
        client_id: ClientId,
        /// Optional `auth.exchange`-style method the backend exposes to swap
        /// an ID token for a backend session cookie.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        exchange: Option<MethodPath>,
        /// Scopes the backend will request from the IdP. Bare-string scopes
        /// per the OIDC convention (e.g. `"openid"`, `"profile"`, `"email"`);
        /// AUTHZ scoping vocabulary is a separate concern (AUTHZ-CORE-4).
        request_scopes: Vec<String>,
    },

    /// Anonymous — the backend accepts unauthenticated callers for some
    /// methods.
    ///
    /// Advertising `Anonymous` is **not** permission to bypass scoping:
    /// per-method `#[plexus::method(public)]` markers gate which methods
    /// anonymous callers may invoke (AUTHZ-CORE-1 / AUTHZ-CORE-2). The
    /// advertisement says "anonymous is one of the accepted shapes"; the
    /// authorization layer says "this specific method is callable that way."
    Anonymous,
}

// ---------------------------------------------------------------------------
// BackendAuthCapabilities
// ---------------------------------------------------------------------------

/// What the backend advertises at `_info`'s `auth_capabilities` field.
///
/// Per AUTHZ-S01-output §2. Backwards-compatible addition: clients that don't
/// know the field continue to ignore it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BackendAuthCapabilities {
    /// Mechanisms the backend supports. May be empty (no auth wired) but
    /// conventionally contains at least one entry; the framework default
    /// emits `[Anonymous]` when no backend has called
    /// `DynamicHub::with_auth_capabilities`.
    pub mechanisms: Vec<AuthMechanism>,

    /// Index into `mechanisms` for the "primary" mechanism a generic client
    /// should try first. `None` means "no opinion; client chooses."
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub default: Option<usize>,
}

impl BackendAuthCapabilities {
    /// Construct a `BackendAuthCapabilities`, validating that `default` (if
    /// present) is in range.
    pub fn new(
        mechanisms: Vec<AuthMechanism>,
        default: Option<usize>,
    ) -> Result<Self, BackendAuthCapabilitiesError> {
        if let Some(idx) = default {
            if idx >= mechanisms.len() {
                return Err(BackendAuthCapabilitiesError::DefaultOutOfRange {
                    default: idx,
                    len: mechanisms.len(),
                });
            }
        }
        Ok(Self {
            mechanisms,
            default,
        })
    }

    /// The default value emitted by `_info` for backends that have not called
    /// `DynamicHub::with_auth_capabilities`: a single `Anonymous` mechanism,
    /// no preferred default.
    ///
    /// This preserves today's substrate behavior (anyone can call) while
    /// signaling "no auth wired" to capability-aware clients.
    pub fn anonymous_default() -> Self {
        Self {
            mechanisms: vec![AuthMechanism::Anonymous],
            default: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- MethodPath -----------------------------------------------------------

    #[test]
    fn method_path_accepts_two_segments() {
        let m = MethodPath::try_new("auth.login").expect("valid");
        assert_eq!(m.as_str(), "auth.login");
        assert_eq!(m.activation(), "auth");
        assert_eq!(m.method(), "login");
    }

    #[test]
    fn method_path_accepts_three_segments() {
        let m = MethodPath::try_new("cone.threads.list").expect("valid");
        assert_eq!(m.activation(), "cone");
        assert_eq!(m.method(), "list");
    }

    #[test]
    fn method_path_accepts_underscored_segments() {
        MethodPath::try_new("cone.send_message").expect("underscores ok");
        MethodPath::try_new("a_b.c_d_e").expect("multiple underscores ok");
    }

    #[test]
    fn method_path_rejects_single_segment() {
        assert!(matches!(
            MethodPath::try_new("login"),
            Err(MethodPathError::InvalidFormat(_))
        ));
    }

    #[test]
    fn method_path_rejects_uppercase() {
        assert!(matches!(
            MethodPath::try_new("Auth.login"),
            Err(MethodPathError::InvalidFormat(_))
        ));
        assert!(matches!(
            MethodPath::try_new("auth.Login"),
            Err(MethodPathError::InvalidFormat(_))
        ));
    }

    #[test]
    fn method_path_rejects_leading_digit() {
        assert!(matches!(
            MethodPath::try_new("1auth.login"),
            Err(MethodPathError::InvalidFormat(_))
        ));
        assert!(matches!(
            MethodPath::try_new("auth.2login"),
            Err(MethodPathError::InvalidFormat(_))
        ));
    }

    #[test]
    fn method_path_rejects_trailing_dot() {
        assert!(matches!(
            MethodPath::try_new("auth."),
            Err(MethodPathError::InvalidFormat(_))
        ));
    }

    #[test]
    fn method_path_rejects_leading_dot() {
        assert!(matches!(
            MethodPath::try_new(".login"),
            Err(MethodPathError::InvalidFormat(_))
        ));
    }

    #[test]
    fn method_path_rejects_wildcard() {
        // Wildcards belong to Scope, not MethodPath.
        assert!(matches!(
            MethodPath::try_new("auth.*"),
            Err(MethodPathError::InvalidFormat(_))
        ));
        assert!(matches!(
            MethodPath::try_new("*"),
            Err(MethodPathError::InvalidFormat(_))
        ));
    }

    #[test]
    fn method_path_rejects_empty() {
        assert_eq!(MethodPath::try_new(""), Err(MethodPathError::Empty));
    }

    #[test]
    fn method_path_rejects_double_dot() {
        assert!(matches!(
            MethodPath::try_new("auth..login"),
            Err(MethodPathError::InvalidFormat(_))
        ));
    }

    #[test]
    fn method_path_serde_roundtrip() {
        let m = MethodPath::try_new("auth.login").unwrap();
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(s, "\"auth.login\"");
        let back: MethodPath = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
    }

    // -- IssuerUrl ------------------------------------------------------------

    #[test]
    fn issuer_url_accepts_https() {
        let u: Url = "https://accounts.example.com/".parse().unwrap();
        let i = IssuerUrl::try_new(u.clone()).expect("https ok");
        assert_eq!(i.as_url(), &u);
    }

    #[test]
    fn issuer_url_accepts_localhost_http() {
        let u: Url = "http://localhost:8080/".parse().unwrap();
        IssuerUrl::try_new(u).expect("http://localhost ok");
        let u2: Url = "http://127.0.0.1:8080/".parse().unwrap();
        IssuerUrl::try_new(u2).expect("http://127.0.0.1 ok");
        let u3: Url = "http://[::1]:8080/".parse().unwrap();
        IssuerUrl::try_new(u3).expect("http://[::1] ok");
    }

    #[test]
    fn issuer_url_rejects_non_localhost_http() {
        let u: Url = "http://accounts.example.com/".parse().unwrap();
        assert!(matches!(
            IssuerUrl::try_new(u),
            Err(IssuerUrlError::InsecureScheme(_))
        ));
    }

    #[test]
    fn issuer_url_rejects_other_schemes() {
        let u: Url = "ftp://example.com/".parse().unwrap();
        assert!(matches!(
            IssuerUrl::try_new(u),
            Err(IssuerUrlError::InsecureScheme(_))
        ));
    }

    #[test]
    fn issuer_url_serde_roundtrip() {
        let u: Url = "https://accounts.example.com/".parse().unwrap();
        let i = IssuerUrl::try_new(u).unwrap();
        let s = serde_json::to_string(&i).unwrap();
        assert_eq!(s, "\"https://accounts.example.com/\"");
        let back: IssuerUrl = serde_json::from_str(&s).unwrap();
        assert_eq!(back, i);
    }

    // -- ClientId -------------------------------------------------------------

    #[test]
    fn client_id_accepts_non_empty() {
        let c = ClientId::try_new("plexus-substrate").unwrap();
        assert_eq!(c.as_str(), "plexus-substrate");
    }

    #[test]
    fn client_id_rejects_empty() {
        assert_eq!(ClientId::try_new(""), Err(ClientIdError::Empty));
    }

    // -- CookieName -----------------------------------------------------------

    #[test]
    fn cookie_name_accepts_valid_token() {
        CookieName::try_new("plexus_session").unwrap();
        CookieName::try_new("Session-Id").unwrap();
        CookieName::try_new("a.b.c").unwrap();
    }

    #[test]
    fn cookie_name_rejects_separator_chars() {
        // RFC 7230 separators that must be rejected: ( ) , / : ; < = > ? @ [ \ ] { } " whitespace
        for ch in [' ', '(', ')', ',', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '{', '}', '"'] {
            let name = format!("a{}b", ch);
            assert!(
                matches!(
                    CookieName::try_new(name.clone()),
                    Err(CookieNameError::InvalidToken(_))
                ),
                "expected reject for {:?}",
                name
            );
        }
    }

    #[test]
    fn cookie_name_rejects_empty() {
        assert_eq!(CookieName::try_new(""), Err(CookieNameError::Empty));
    }

    // -- HeaderName -----------------------------------------------------------

    #[test]
    fn header_name_normalizes_to_lowercase() {
        let h = HeaderName::try_new("Authorization").unwrap();
        assert_eq!(h.as_str(), "authorization");

        // Different cases compare equal because both normalize.
        let h2 = HeaderName::try_new("AUTHORIZATION").unwrap();
        let h3 = HeaderName::try_new("authorization").unwrap();
        assert_eq!(h, h2);
        assert_eq!(h, h3);
    }

    #[test]
    fn header_name_rejects_invalid_chars() {
        assert!(matches!(
            HeaderName::try_new("X Header"),
            Err(HeaderNameError::InvalidToken(_))
        ));
        assert!(matches!(
            HeaderName::try_new("X:Header"),
            Err(HeaderNameError::InvalidToken(_))
        ));
    }

    #[test]
    fn header_name_rejects_empty() {
        assert_eq!(HeaderName::try_new(""), Err(HeaderNameError::Empty));
    }

    // -- AuthMechanism serialization ------------------------------------------

    #[test]
    fn auth_mechanism_bearer_round_trip() {
        let m = AuthMechanism::Bearer {
            header: HeaderName::try_new("authorization").unwrap(),
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(
            v,
            json!({
                "kind": "bearer",
                "header": "authorization"
            })
        );
        let back: AuthMechanism = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn auth_mechanism_cookie_round_trip_minimal() {
        // refresh / logout omitted — exercise the skip_serializing_if path.
        let m = AuthMechanism::Cookie {
            cookie: CookieName::try_new("plexus_session").unwrap(),
            login: MethodPath::try_new("auth.login").unwrap(),
            refresh: None,
            logout: None,
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(
            v,
            json!({
                "kind": "cookie",
                "cookie": "plexus_session",
                "login": "auth.login"
            }),
            "refresh / logout should be omitted when None"
        );
        let back: AuthMechanism = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn auth_mechanism_cookie_round_trip_full() {
        let m = AuthMechanism::Cookie {
            cookie: CookieName::try_new("plexus_session").unwrap(),
            login: MethodPath::try_new("auth.login").unwrap(),
            refresh: Some(MethodPath::try_new("auth.refresh").unwrap()),
            logout: Some(MethodPath::try_new("auth.logout").unwrap()),
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(
            v,
            json!({
                "kind": "cookie",
                "cookie": "plexus_session",
                "login": "auth.login",
                "refresh": "auth.refresh",
                "logout": "auth.logout"
            })
        );
        let back: AuthMechanism = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn auth_mechanism_oidc_round_trip() {
        let m = AuthMechanism::Oidc {
            issuer: IssuerUrl::try_new("https://accounts.example.com/".parse().unwrap()).unwrap(),
            client_id: ClientId::try_new("plexus-substrate").unwrap(),
            exchange: Some(MethodPath::try_new("auth.exchange").unwrap()),
            request_scopes: vec!["openid".into(), "profile".into(), "email".into()],
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(
            v,
            json!({
                "kind": "oidc",
                "issuer": "https://accounts.example.com/",
                "client_id": "plexus-substrate",
                "exchange": "auth.exchange",
                "request_scopes": ["openid", "profile", "email"]
            })
        );
        let back: AuthMechanism = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn auth_mechanism_anonymous_round_trip() {
        let m = AuthMechanism::Anonymous;
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v, json!({ "kind": "anonymous" }));
        let back: AuthMechanism = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    // -- BackendAuthCapabilities ---------------------------------------------

    #[test]
    fn backend_auth_capabilities_constructs_with_valid_default() {
        let caps = BackendAuthCapabilities::new(
            vec![
                AuthMechanism::Bearer {
                    header: HeaderName::try_new("authorization").unwrap(),
                },
                AuthMechanism::Cookie {
                    cookie: CookieName::try_new("plexus_session").unwrap(),
                    login: MethodPath::try_new("auth.login").unwrap(),
                    refresh: None,
                    logout: None,
                },
            ],
            Some(1),
        )
        .unwrap();
        assert_eq!(caps.default, Some(1));
        assert_eq!(caps.mechanisms.len(), 2);
    }

    #[test]
    fn backend_auth_capabilities_rejects_out_of_range_default() {
        let res = BackendAuthCapabilities::new(
            vec![AuthMechanism::Anonymous],
            Some(5),
        );
        assert_eq!(
            res,
            Err(BackendAuthCapabilitiesError::DefaultOutOfRange {
                default: 5,
                len: 1,
            })
        );
    }

    #[test]
    fn backend_auth_capabilities_rejects_default_for_empty_mechanisms() {
        let res = BackendAuthCapabilities::new(vec![], Some(0));
        assert_eq!(
            res,
            Err(BackendAuthCapabilitiesError::DefaultOutOfRange {
                default: 0,
                len: 0,
            })
        );
    }

    #[test]
    fn backend_auth_capabilities_anonymous_default() {
        let caps = BackendAuthCapabilities::anonymous_default();
        assert_eq!(caps.mechanisms, vec![AuthMechanism::Anonymous]);
        assert_eq!(caps.default, None);

        // Wire format: default is omitted when None.
        let v = serde_json::to_value(&caps).unwrap();
        assert_eq!(
            v,
            json!({
                "mechanisms": [{ "kind": "anonymous" }]
            }),
            "default should be omitted when None"
        );
    }

    #[test]
    fn backend_auth_capabilities_full_wire_form_matches_spec() {
        // The canonical example from AUTHZ-S01-output §2 (verbatim).
        let caps = BackendAuthCapabilities::new(
            vec![
                AuthMechanism::Bearer {
                    header: HeaderName::try_new("authorization").unwrap(),
                },
                AuthMechanism::Cookie {
                    cookie: CookieName::try_new("plexus_session").unwrap(),
                    login: MethodPath::try_new("auth.login").unwrap(),
                    refresh: Some(MethodPath::try_new("auth.refresh").unwrap()),
                    logout: Some(MethodPath::try_new("auth.logout").unwrap()),
                },
                AuthMechanism::Oidc {
                    issuer: IssuerUrl::try_new(
                        "https://accounts.example.com/".parse().unwrap(),
                    )
                    .unwrap(),
                    client_id: ClientId::try_new("plexus-substrate").unwrap(),
                    exchange: Some(MethodPath::try_new("auth.exchange").unwrap()),
                    request_scopes: vec!["openid".into(), "profile".into(), "email".into()],
                },
            ],
            Some(1),
        )
        .unwrap();

        let v = serde_json::to_value(&caps).unwrap();
        assert_eq!(
            v,
            json!({
                "mechanisms": [
                    { "kind": "bearer", "header": "authorization" },
                    {
                        "kind": "cookie",
                        "cookie": "plexus_session",
                        "login": "auth.login",
                        "refresh": "auth.refresh",
                        "logout": "auth.logout"
                    },
                    {
                        "kind": "oidc",
                        "issuer": "https://accounts.example.com/",
                        "client_id": "plexus-substrate",
                        "exchange": "auth.exchange",
                        "request_scopes": ["openid", "profile", "email"]
                    }
                ],
                "default": 1
            })
        );

        // Round-trip back.
        let back: BackendAuthCapabilities = serde_json::from_value(v).unwrap();
        assert_eq!(back, caps);
    }
}
