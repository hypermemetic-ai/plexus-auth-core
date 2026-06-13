//! AUTH-2's spike conditions as the OIDC validator's test matrix (UT-1).
//!
//! Per the UT-S01 decision ("AUTH-2's method absorbed as the validator
//! test matrix") plus the AUTH-8 caching policy behaviors:
//!
//! | # | Condition | Test |
//! |---|---|---|
//! | 1 | valid token round-trip (non-empty sub/iss, future exp) | `valid_token_round_trip` |
//! | 2 | wrong `iss` rejected | `wrong_issuer_rejected` |
//! | 3 | wrong `aud` rejected | `wrong_audience_rejected` |
//! | 4 | expired `exp` rejected, zero grace | `expired_token_rejected` |
//! | 5 | tampered payload rejected (auth error, not transport) | `tampered_token_rejected` |
//! | 6 | kid rotation: old kid stays cached, new kid → exactly one refresh | `kid_rotation_triggers_exactly_one_refresh` |
//! | 7 | unknown kid → one refresh then reject | `unknown_kid_rejected_after_exactly_one_refresh` |
//! | 8 | offline + warm cache → degraded validation, future-exp only | `offline_with_warm_cache_degrades_and_validates` |
//! | 9 | offline + cold cache → reject | `offline_with_cold_cache_errors` |
//! | 10 | `org_id` extraction → typed TenantId | `org_id_claim_becomes_typed_tenant` |
//! | 11 | missing `org_id` → valid but tenantless | `missing_org_id_is_valid_but_tenantless` |
//!
//! **No network**: the IdP is a [`FixtureIdp`] implementing
//! [`JwksFetcher`] — the injected-fetcher seam the module is designed
//! around. Fixture key material: two 2048-bit RSA keypairs generated
//! offline (openssl) with their public halves pre-rendered as JWK
//! constants below; nothing here can mint production-trusted tokens
//! because production validators discover keys from their configured
//! issuer, not from these fixtures.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;

use plexus_auth_core::oidc::{
    Audience, FetchError, FetchedDocument, JwksFetcher, OidcConfig, OidcError,
    OidcSessionValidator, OidcValidator,
};
use plexus_auth_core::{IssuerUrl, SessionValidator};

// ─── Fixture key material ───────────────────────────────────────────────

const ISSUER: &str = "https://idp.test";
const AUDIENCE: &str = "plexus:test";

const KID_1: &str = "ut1-key-1";
const KID_2: &str = "ut1-key-2";

const KEY_1_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDRK77i+LgwjT95
0Uq+AQQe9Ls/PamwwyIrbCK+23//1oufPKD6x8TSWBVRXX5adtks140U6WU89Chs
sZTqyGFP23RjXrXTE9YXUAxL+5SKfoLVmZ0frz1kaCA09oW7+J6GczbYCIp9HNr3
dF4klIh2zqzoEYS4bNgZpI/xWHIWX2BAmXOg3Nb1/F3Z6rFWgxft3QkG9+/SftJ5
wmUVqvwa9+IG/TkNhE8VTfmfm/KRvMIbinckoUDoiawAf2sk3SOS1r6XHwPV2AjO
mukGfPQ+6BaggFOqzls7mH2n9KEsASNHDAKz242sSR+mYPF4afrXSzeDsUenMK0l
4kmzw1cVAgMBAAECggEABLrihCtvrtli2BRdhlJrj2+lVFbGoZKoESdO2dYI3PYz
DhTG5yThVIhdYwukMdOCMbtmG1Tzzx8OUvbpES4a1T13MlAP+If4TWqn/Ifh4gfe
WYoxvWevEbgxEkGI4KlMnGm6kcQPraibYwEkp9scAuPFkTHkOG9tq5bHEoQXgF35
Q1OxUI+S2YFH+5gY9pUWqLTkhc1iCb2b0YWZeYVs7eQvblajiCZagNXgWDBf05sE
AylUFMUzJV12Z0udyQal8H7ObuISxa6o57124Ib4x0V/LVXtAbdZQMru/Ymx6xxk
haBt8htLcFZdRC/RDCPNsd0fjsrqpARIF8jo+rgzeQKBgQD9BDU9zph03HYqHQZU
caizwE+G7fXswuhqlxmy94L/zL/Y2XpLMzDaPjv3S8wOrYQNx8uJpxycgJ2K7slM
M9qKL3UlkjsuS7DtGLFrvBQyC2KVMrMPBaSNOwnhSVWCyCRsSiiuACIFAWS9icS3
Eb1MqYAg2gdtB3QvhDb75IBYwwKBgQDToy3b8/h6ybIqmqz9bJ4QQwzHEs43uZ/P
VXVkiXHXHJ9zfq/dIjSYkIbsNJhD8CrzhOrvM11Fpah0i1EN5uqYJ3wKC13ZCWMe
wDZstYipoVYY80/M02Vnt0iEGsoNUojTqMWxixbkSHbvUUgQQpkEQrnqHEfV+LXo
X4JnyNbTRwKBgFZsw4rzMNxqGerUsz7Q/CE6RW//hIt1IFKYfmzFYvfhhn6Z+s4J
FFzX+T/FolQ5LOxQHNROQtWqkSXN3vCqnbGp+Ef3JUPxEuRKFQCJ5BQcE3aHNOai
tMyRKBTOKelcWCStSCv3W6d+DF052/n0k0bGdz/BedviOeupK+bq7HRlAoGAeaxA
+0miO4WmBtRyTCicHyFNQU5QfL0dYafyG+DhMBjmmxHkra+yqVu+FiKOv9BeAS8T
mn3fS+FXndlSujld+igJKgUq6VJ6R/2dzJX5gfydcS7BXDLVA/HdoQV90Hb47ycC
sXYTrR70MdZ7Jc4EBu0N0ch8jEm222e9o0lWKJUCgYBXxOLoBstghiOh7+q2C3l4
g8jv2q8ISuQn2Ov+e6w9TLX9FDAGMBt+7XTeQvB4UHnzugPL4ThHPzaHSZZ2MSe0
cc/8jPBcPehKNhhgDUFkmptSZn7hFSAkzdjoC4yYxu9OsftU9M3Fvg2awbJ/j78w
ibtF9Ayucd2RXBc2n+6vZg==
-----END PRIVATE KEY-----";

const KEY_2_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/iZM3Lp2jX5h6
T5hf/XtB9Vw2qSyEHXgvDMh7djnhOJnBm7g0375g+xtv1T2MuJgomsaU5WPnOUq1
8imYFlQPjstvWSU8Kw7JKYmdkMhjlyOQJFfH/Cj2BvoQE3HE67juVOKsybX0FamA
PPg4/e8RDMz5EvKVNNnfH/Eo71rqb0fX57BCxTcQscZUOmayi9XjyMq35dUeGFhT
GAbITVrfI+57TuADpXbotljeJI8E0knAgz/hzGgucl03sA19UEk+k5tHVBauNcFG
/7HH7C3DUsWDxnRMrTZ5m18DsFwkE7s+TT/r9fcZh32kt1rQ5CwWCf4uyZVOJOsM
RJLX6UaBAgMBAAECggEAMqU9AP1Zf2Z6mfTL9K3A1rr7DBUFiVWFfuNha4viWBQw
S8pSFeEHpPsg0RxQbxIsYagzVBGnre8vOxbyOp3E0mxOjH3E47j66uQJ2Fj9M6A2
Lhn+AApEBnHn0zJhBdHSj2pwmYGolAbaT+dPNzql6Rs6Y63H6P4VkfMPQGSx5ITc
6B+//A3LiZAPWbe4QDu4dN3PAykzjTEvs2O+qXSG2Bj+bv4d5zG6Lr4YQrfVNUO1
edH40uDwgt41TEwdNPH0cDwdaW3fLS7xw8Htmyy2QKK1ABxq36qoJaNIu7jaym1I
+JAIPLnCtoQFilTCDSz2B8F80nR5ZcqyjZczuwPVlQKBgQDrN6s9ov7IUlikhCY2
hjcnrzCxOKzYT7s3Jrr4kcBt7ulQgolo6c07F3rTSh2RVe5TCczU+nQ3ajIZ9+Z0
ntILTpnSp9+EIfpt+k0NzKiGOKzDq00bGIDlt0gTNvJ0vnHH40x1jQuZrepzXEJu
zfRY7z889AyP5/tWXKMyGeBV+wKBgQDQdeqxWlSzrvm61YOmfX5fz8egOfqPt47q
ebU7/c4OEJlNvX6G9mUlot74KOhPBX2XWMAKPyS7C0TEF1VIT71vUguEM5CDjW0z
FZHea/KLd8i21NVtpfYK4PkK9hjpjLh8+3dvUGTL42Gm9Z7bShzR8b/jXtqRsY/g
0kqRRKb4swKBgEUHXFDFYeImEG+PfKtprgwOZMrNqCP/GiEwU5SZKZDZmU0QUgUh
ACLEXD5ftNevETb7XEpwieStXLC0SMSWy2uYEJp6u6TKV/UojK5tDlP9k+4Eeqdm
BIXlyNgiuvq53ShdM1YYI3xhRrm+LJzaAkiLRdK8iGc/HEqW+ym74FM7AoGAavbW
gkJzi++QvMmqT9e87LTVHeYiJ3RspOvmju3guV7TCwzcy6vKotE7z+JNsZ6DnxEv
GRLlagSSOHwwinZAIcrble5PjPEYw0miG5sQTXgdSZNUIHs0EMj3gSReDBjk4Vy3
ICsETYpTJTSLWsJgn2mIqMaXKIMP7LB7CqdLdfkCgYEAmj473lfYT1iLmEocy/+C
b/5rWyUCu4XxBmLVdJcJVezQpXg3Xyr9v84jqHg8PFEpIAEqE1uykJ+i3GaSYJae
y76z91PE0xvQex21id3PvJoJo5w4FUsVWAx0HorzOILaLYohoYvLfEe9xEvlHFrd
h+pCFWMecrkGFQZJTLoU4FY=
-----END PRIVATE KEY-----";

/// Public JWK for `KEY_1_PEM` (n/e computed offline from the modulus).
const JWK_1: &str = r#"{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "ut1-key-1", "n": "0Su-4vi4MI0_edFKvgEEHvS7Pz2psMMiK2wivtt__9aLnzyg-sfE0lgVUV1-WnbZLNeNFOllPPQobLGU6shhT9t0Y1610xPWF1AMS_uUin6C1ZmdH689ZGggNPaFu_iehnM22AiKfRza93ReJJSIds6s6BGEuGzYGaSP8VhyFl9gQJlzoNzW9fxd2eqxVoMX7d0JBvfv0n7SecJlFar8GvfiBv05DYRPFU35n5vykbzCG4p3JKFA6ImsAH9rJN0jkta-lx8D1dgIzprpBnz0PugWoIBTqs5bO5h9p_ShLAEjRwwCs9uNrEkfpmDxeGn610s3g7FHpzCtJeJJs8NXFQ", "e": "AQAB"}"#;

/// Public JWK for `KEY_2_PEM`.
const JWK_2: &str = r#"{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "ut1-key-2", "n": "v4mTNy6do1-Yek-YX_17QfVcNqkshB14LwzIe3Y54TiZwZu4NN--YPsbb9U9jLiYKJrGlOVj5zlKtfIpmBZUD47Lb1klPCsOySmJnZDIY5cjkCRXx_wo9gb6EBNxxOu47lTirMm19BWpgDz4OP3vEQzM-RLylTTZ3x_xKO9a6m9H1-ewQsU3ELHGVDpmsovV48jKt-XVHhhYUxgGyE1a3yPue07gA6V26LZY3iSPBNJJwIM_4cxoLnJdN7ANfVBJPpObR1QWrjXBRv-xx-wtw1LFg8Z0TK02eZtfA7BcJBO7Pk0_6_X3GYd9pLda0OQsFgn-LsmVTiTrDESS1-lGgQ", "e": "AQAB"}"#;

// ─── Fixture IdP (injected fetcher) ─────────────────────────────────────

/// An in-process "IdP": serves a discovery document and a JWKS, counts
/// fetches, and can be flipped offline. This is the no-network seam the
/// validator is designed around.
struct FixtureIdp {
    /// JWKs currently published (rotate by replacing this).
    jwks: Mutex<Vec<&'static str>>,
    /// `Cache-Control` header served with the JWKS response.
    cache_control: Mutex<Option<String>>,
    /// Issuer the discovery document claims (normally `ISSUER`; tests
    /// can lie to exercise the issuer-mismatch defense).
    discovery_issuer: Mutex<String>,
    offline: AtomicBool,
    discovery_fetches: AtomicUsize,
    jwks_fetches: AtomicUsize,
}

impl FixtureIdp {
    fn new(jwks: Vec<&'static str>) -> Arc<Self> {
        Arc::new(Self {
            jwks: Mutex::new(jwks),
            cache_control: Mutex::new(None),
            discovery_issuer: Mutex::new(ISSUER.to_string()),
            offline: AtomicBool::new(false),
            discovery_fetches: AtomicUsize::new(0),
            jwks_fetches: AtomicUsize::new(0),
        })
    }

    fn set_offline(&self, offline: bool) {
        self.offline.store(offline, Ordering::SeqCst);
    }

    fn rotate_jwks(&self, jwks: Vec<&'static str>) {
        *self.jwks.lock().unwrap() = jwks;
    }

    fn set_cache_control(&self, value: Option<&str>) {
        *self.cache_control.lock().unwrap() = value.map(str::to_string);
    }

    fn jwks_fetch_count(&self) -> usize {
        self.jwks_fetches.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl JwksFetcher for FixtureIdp {
    async fn fetch(&self, url: &url::Url) -> Result<FetchedDocument, FetchError> {
        if self.offline.load(Ordering::SeqCst) {
            return Err(FetchError("fixture IdP offline".into()));
        }
        match url.path() {
            "/.well-known/openid-configuration" => {
                self.discovery_fetches.fetch_add(1, Ordering::SeqCst);
                let issuer = self.discovery_issuer.lock().unwrap().clone();
                Ok(FetchedDocument {
                    body: json!({
                        "issuer": issuer,
                        "jwks_uri": format!("{ISSUER}/jwks.json"),
                        "token_endpoint": format!("{ISSUER}/oauth/token"),
                        "id_token_signing_alg_values_supported": ["RS256"],
                    })
                    .to_string(),
                    cache_control: None,
                })
            }
            "/jwks.json" => {
                self.jwks_fetches.fetch_add(1, Ordering::SeqCst);
                let keys = self.jwks.lock().unwrap().join(",");
                Ok(FetchedDocument {
                    body: format!(r#"{{"keys": [{keys}]}}"#),
                    cache_control: self.cache_control.lock().unwrap().clone(),
                })
            }
            other => Err(FetchError(format!("fixture IdP has no route {other}"))),
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn config() -> OidcConfig {
    OidcConfig::new(
        IssuerUrl::try_new(ISSUER.parse().unwrap()).unwrap(),
        Audience::try_new(AUDIENCE).unwrap(),
    )
}

fn validator(idp: &Arc<FixtureIdp>) -> OidcValidator {
    OidcValidator::with_fetcher(config(), Arc::clone(idp) as Arc<dyn JwksFetcher>)
}

/// Standard valid claim set; tests override fields as needed.
fn claims() -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert("sub".into(), json!("user_alice"));
    m.insert("iss".into(), json!(ISSUER));
    m.insert("aud".into(), json!(AUDIENCE));
    m.insert("exp".into(), json!(now() + 3600));
    m.insert("iat".into(), json!(now() - 10));
    m
}

fn mint(kid: &str, pem: &str, claims: serde_json::Map<String, serde_json::Value>) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        &serde_json::Value::Object(claims),
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn mint_valid() -> String {
    mint(KID_1, KEY_1_PEM, claims())
}

// ─── 1. Valid round-trip ────────────────────────────────────────────────

#[tokio::test]
async fn valid_token_round_trip() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);

    let mut c = claims();
    c.insert("org_id".into(), json!("org_hypermemetic"));
    c.insert("roles".into(), json!(["admin"]));
    c.insert("username".into(), json!("alice"));
    let verified = v.validate_token(&mint(KID_1, KEY_1_PEM, c)).await.unwrap();

    // AUTH-2 pass condition: non-empty sub/iss, future exp.
    assert_eq!(verified.user().user_id(), "user_alice");
    assert_eq!(verified.user().issuer(), ISSUER);
    assert!(verified.user().expires_at() > now());
    assert_eq!(verified.roles(), ["admin".to_string()]);
    assert_eq!(verified.username(), Some("alice"));

    // The minted AuthContext is authenticated and carries the tenancy
    // claim under both keys (UT-S01 D3 deprecation window).
    let ctx = verified.into_auth_context();
    assert!(ctx.is_authenticated());
    assert_eq!(ctx.user_id, "user_alice");
    assert!(ctx.has_role("admin"));
    assert_eq!(
        ctx.get_metadata_string("org_id"),
        Some("org_hypermemetic".to_string())
    );
    assert_eq!(
        ctx.get_metadata_string("tenant_id"),
        Some("org_hypermemetic".to_string())
    );
    assert_eq!(
        ctx.tenant_id().map(|t| t.as_str().to_string()),
        Some("org_hypermemetic".to_string())
    );

    // Cold start cost: exactly one discovery + one JWKS fetch.
    assert_eq!(idp.discovery_fetches.load(Ordering::SeqCst), 1);
    assert_eq!(idp.jwks_fetch_count(), 1);
}

#[tokio::test]
async fn second_validation_hits_warm_cache() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    v.validate_token(&mint_valid()).await.unwrap();
    v.validate_token(&mint_valid()).await.unwrap();
    // Default TTL is 3600 s — the second call must not refetch.
    assert_eq!(idp.jwks_fetch_count(), 1);
}

// ─── 2/3. Wrong iss / aud ───────────────────────────────────────────────

#[tokio::test]
async fn wrong_issuer_rejected() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    let mut c = claims();
    c.insert("iss".into(), json!("https://evil.test"));
    let err = v.validate_token(&mint(KID_1, KEY_1_PEM, c)).await.unwrap_err();
    assert!(matches!(err, OidcError::WrongIssuer), "{err}");
}

#[tokio::test]
async fn wrong_audience_rejected() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    let mut c = claims();
    c.insert("aud".into(), json!("plexus:other-backend"));
    let err = v.validate_token(&mint(KID_1, KEY_1_PEM, c)).await.unwrap_err();
    assert!(matches!(err, OidcError::WrongAudience), "{err}");
}

// ─── 4. Expiry (zero grace) ─────────────────────────────────────────────

#[tokio::test]
async fn expired_token_rejected() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    let mut c = claims();
    // 10 s past — inside jsonwebtoken's default 60 s leeway, so this also
    // pins that the validator zeroed the leeway (AUTH-8: no grace).
    c.insert("exp".into(), json!(now() - 10));
    let err = v.validate_token(&mint(KID_1, KEY_1_PEM, c)).await.unwrap_err();
    assert!(matches!(err, OidcError::Expired), "{err}");
}

#[tokio::test]
async fn iat_in_future_rejected() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    let mut c = claims();
    c.insert("iat".into(), json!(now() + 3600));
    let err = v.validate_token(&mint(KID_1, KEY_1_PEM, c)).await.unwrap_err();
    assert!(matches!(err, OidcError::IssuedInFuture { .. }), "{err}");
}

// ─── 5. Tampering / forgery ─────────────────────────────────────────────

#[tokio::test]
async fn tampered_token_rejected() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);

    // Splice the payload of a different (also well-formed) token into a
    // validly signed one: header₁.payload₂.signature₁.
    let t1 = mint_valid();
    let mut c2 = claims();
    c2.insert("sub".into(), json!("user_mallory"));
    c2.insert("roles".into(), json!(["admin"]));
    let t2 = mint(KID_1, KEY_1_PEM, c2);

    let p1: Vec<&str> = t1.split('.').collect();
    let p2: Vec<&str> = t2.split('.').collect();
    let spliced = format!("{}.{}.{}", p1[0], p2[1], p1[2]);

    let err = v.validate_token(&spliced).await.unwrap_err();
    assert!(matches!(err, OidcError::InvalidSignature), "{err}");
}

#[tokio::test]
async fn token_signed_by_foreign_key_rejected() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    // Signed with key 2 but claiming kid 1: signature check must fail.
    let err = v
        .validate_token(&mint(KID_1, KEY_2_PEM, claims()))
        .await
        .unwrap_err();
    assert!(matches!(err, OidcError::InvalidSignature), "{err}");
}

#[tokio::test]
async fn non_rs256_token_rejected_without_fetching() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    // HS256 token — the shared-secret shape 74103adf indicts. Rejected at
    // the header gate, before any key fetch.
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID_1.to_string());
    let token = encode(
        &header,
        &serde_json::Value::Object(claims()),
        &EncodingKey::from_secret(b"shared-secret"),
    )
    .unwrap();
    let err = v.validate_token(&token).await.unwrap_err();
    assert!(matches!(err, OidcError::UnsupportedAlgorithm(_)), "{err}");
    assert_eq!(idp.jwks_fetch_count(), 0);
}

#[tokio::test]
async fn kid_less_token_rejected() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    let token = encode(
        &Header::new(Algorithm::RS256), // no kid
        &serde_json::Value::Object(claims()),
        &EncodingKey::from_rsa_pem(KEY_1_PEM.as_bytes()).unwrap(),
    )
    .unwrap();
    let err = v.validate_token(&token).await.unwrap_err();
    assert!(matches!(err, OidcError::MissingKeyId), "{err}");
}

#[tokio::test]
async fn missing_sub_rejected() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    let mut c = claims();
    c.remove("sub");
    let err = v.validate_token(&mint(KID_1, KEY_1_PEM, c)).await.unwrap_err();
    assert!(matches!(err, OidcError::MalformedToken(_)), "{err}");
}

// ─── 6/7. kid rotation + unknown kid (AUTH-8) ───────────────────────────

#[tokio::test]
async fn kid_rotation_triggers_exactly_one_refresh() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);

    // Warm the cache with key 1.
    v.validate_token(&mint_valid()).await.unwrap();
    assert_eq!(idp.jwks_fetch_count(), 1);

    // IdP rotates: publishes key 2 alongside key 1 (the UT-S01 rotation
    // recipe — old kid stays published until old tokens drain).
    idp.rotate_jwks(vec![JWK_1, JWK_2]);

    // Old-kid token: still served from cache, no refetch.
    v.validate_token(&mint_valid()).await.unwrap();
    assert_eq!(idp.jwks_fetch_count(), 1);

    // New-kid token: kid-miss → exactly one refresh → validates.
    v.validate_token(&mint(KID_2, KEY_2_PEM, claims())).await.unwrap();
    assert_eq!(idp.jwks_fetch_count(), 2);

    // Both kids now cached; neither costs another fetch.
    v.validate_token(&mint_valid()).await.unwrap();
    v.validate_token(&mint(KID_2, KEY_2_PEM, claims())).await.unwrap();
    assert_eq!(idp.jwks_fetch_count(), 2);
}

#[tokio::test]
async fn unknown_kid_rejected_after_exactly_one_refresh() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    v.validate_token(&mint_valid()).await.unwrap();
    assert_eq!(idp.jwks_fetch_count(), 1);

    // A token naming a kid the IdP never published: one refresh, then
    // reject — not a refresh loop.
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("ut1-key-404".to_string());
    let token = encode(
        &header,
        &serde_json::Value::Object(claims()),
        &EncodingKey::from_rsa_pem(KEY_1_PEM.as_bytes()).unwrap(),
    )
    .unwrap();
    let err = v.validate_token(&token).await.unwrap_err();
    assert!(matches!(err, OidcError::UnknownKeyId(ref k) if k == "ut1-key-404"), "{err}");
    assert_eq!(idp.jwks_fetch_count(), 2);
}

// ─── 8/9. Offline behavior (AUTH-8 degraded mode) ───────────────────────

#[tokio::test]
async fn offline_with_warm_cache_degrades_and_validates() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    // max-age=0 forces a refresh attempt on every validation, so going
    // offline is observed immediately.
    idp.set_cache_control(Some("max-age=0"));
    let v = validator(&idp);

    // Warm the cache online.
    v.validate_token(&mint_valid()).await.unwrap();

    // IdP goes dark. Cached keys keep serving future-exp tokens.
    idp.set_offline(true);
    v.validate_token(&mint_valid())
        .await
        .expect("warm cache must keep validating future-exp tokens while offline");

    // ... but expired tokens get no offline grace (exp is enforced with
    // zero leeway regardless of degraded mode).
    let mut c = claims();
    c.insert("exp".into(), json!(now() - 10));
    let err = v.validate_token(&mint(KID_1, KEY_1_PEM, c)).await.unwrap_err();
    assert!(matches!(err, OidcError::Expired), "{err}");

    // Recovery: IdP returns; the next validation refreshes fresh keys.
    idp.set_offline(false);
    let before = idp.jwks_fetch_count();
    v.validate_token(&mint_valid()).await.unwrap();
    assert!(idp.jwks_fetch_count() > before, "restored IdP must be refetched");
}

#[tokio::test]
async fn offline_with_cold_cache_errors() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    idp.set_offline(true);
    let v = validator(&idp);
    let err = v.validate_token(&mint_valid()).await.unwrap_err();
    // Cold + offline: nothing cached to degrade onto. (Discovery is the
    // first fetch to fail.)
    assert!(
        matches!(err, OidcError::Discovery(_) | OidcError::JwksUnavailable(_)),
        "{err}"
    );
}

#[tokio::test]
async fn offline_kid_miss_with_stale_cache_rejects_unknown_kid() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    v.validate_token(&mint_valid()).await.unwrap();
    idp.set_offline(true);

    // kid-miss while offline: the one refresh fails, stale cache has no
    // such kid → UnknownKeyId (degraded mode does not invent keys).
    let err = v
        .validate_token(&mint(KID_2, KEY_2_PEM, claims()))
        .await
        .unwrap_err();
    assert!(matches!(err, OidcError::UnknownKeyId(_)), "{err}");
}

// ─── 10/11. org_id → tenancy ────────────────────────────────────────────

#[tokio::test]
async fn org_id_claim_becomes_typed_tenant() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    let mut c = claims();
    c.insert("org_id".into(), json!("org_hypermemetic"));
    let verified = v.validate_token(&mint(KID_1, KEY_1_PEM, c)).await.unwrap();
    assert_eq!(
        verified.tenant_id().map(|t| t.as_str()),
        Some("org_hypermemetic")
    );
    assert_eq!(
        verified.user().tenant_id().map(|t| t.as_str()),
        Some("org_hypermemetic")
    );
}

#[tokio::test]
async fn missing_org_id_is_valid_but_tenantless() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    let verified = v.validate_token(&mint_valid()).await.unwrap();
    assert!(verified.tenant_id().is_none());

    // The AuthContext is authenticated but carries no tenancy metadata.
    let ctx = verified.into_auth_context();
    assert!(ctx.is_authenticated());
    assert!(ctx.tenant_id().is_none());
    assert_eq!(ctx.get_metadata_string("org_id"), None);
}

#[tokio::test]
async fn malformed_org_id_rejected() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    let mut c = claims();
    c.insert("org_id".into(), json!("evil\u{0000}org"));
    let err = v.validate_token(&mint(KID_1, KEY_1_PEM, c)).await.unwrap_err();
    assert!(matches!(err, OidcError::InvalidTenantClaim(_)), "{err}");
}

// ─── Discovery defenses ─────────────────────────────────────────────────

#[tokio::test]
async fn discovery_issuer_mismatch_rejected() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    *idp.discovery_issuer.lock().unwrap() = "https://impostor.test".to_string();
    let v = validator(&idp);
    let err = v.validate_token(&mint_valid()).await.unwrap_err();
    assert!(matches!(err, OidcError::Discovery(_)), "{err}");
}

// ─── SessionValidator surface ───────────────────────────────────────────

#[tokio::test]
async fn session_validator_accepts_cookie_and_bare_token() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let sv = OidcSessionValidator::new(validator(&idp));

    let mut c = claims();
    c.insert("org_id".into(), json!("org_acme"));
    let token = mint(KID_1, KEY_1_PEM, c);

    // Cookie-header shape (the WS-upgrade path).
    let ctx = sv
        .validate(&format!("access_token={token}; other=1"))
        .await
        .expect("valid cookie token must authenticate");
    assert!(ctx.is_authenticated());
    assert_eq!(ctx.user_id, "user_alice");
    assert_eq!(
        ctx.tenant_id().map(|t| t.as_str().to_string()),
        Some("org_acme".to_string())
    );

    // Bare-token shape (synapse `-t <jwt>`).
    let ctx2 = sv.validate(&token).await.expect("bare token must authenticate");
    assert_eq!(ctx2.user_id, "user_alice");
}

#[tokio::test]
async fn session_validator_maps_all_rejections_to_none() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let sv = OidcSessionValidator::new(validator(&idp));

    // Expired.
    let mut c = claims();
    c.insert("exp".into(), json!(now() - 10));
    assert!(sv
        .validate(&format!("access_token={}", mint(KID_1, KEY_1_PEM, c)))
        .await
        .is_none());

    // Garbage.
    assert!(sv.validate("access_token=not-a-jwt").await.is_none());
}

#[tokio::test]
async fn session_id_prefers_sid_claim() {
    let idp = FixtureIdp::new(vec![JWK_1]);
    let v = validator(&idp);
    let mut c = claims();
    c.insert("sid".into(), json!("sess-oidc-1"));
    let verified = v.validate_token(&mint(KID_1, KEY_1_PEM, c)).await.unwrap();
    assert_eq!(verified.session_id(), "sess-oidc-1");

    // Without sid/jti the session id is still non-empty (signature
    // segment) so the AuthContext reports authenticated.
    let verified2 = v.validate_token(&mint_valid()).await.unwrap();
    assert!(!verified2.session_id().is_empty());
}
