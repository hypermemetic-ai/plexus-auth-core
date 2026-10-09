//! IDENTITY-13: provider adapters turn each provider's credential into
//! Plexus types. Two fixture issuers stand in for the providers over the
//! validator's injected fetcher (no network): one shaped like Auth0 (an
//! issuer with a trailing slash, `auth0|` subjects, a namespaced roles
//! claim) and one shaped like plexus-idp. Nostr events are signed with a
//! real key, as a client would.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use nostr::event::{EventBuilder, FinalizeEvent, Kind, Tag};
use nostr::key::Keys;
use nostr::nips::nip19::ToBech32;
use serde_json::json;

use plexus_auth_core::adapters::{Carriers, Nip98Adapter, OidcAdapter};
use plexus_auth_core::identity::{AuthenticatorChain, Issuer, Principal};
use plexus_auth_core::oidc::{FetchError, FetchedDocument, JwksFetcher, OidcValidator};
use plexus_auth_core::{AuthContext, SessionValidator};

const AUTH0: &str = "https://acme.auth0.com/";
const AUTH0_AUD: &str = "https://menger.example";
const ROLES_CLAIM: &str = "https://menger.example/roles";
const IDP: &str = "http://127.0.0.1:4461";
const IDP_AUD: &str = "plexus:menger";
const SERVICE: &str = "ws://127.0.0.1:4455/";

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

const JWK_1: &str = r#"{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "acme-1", "n": "0Su-4vi4MI0_edFKvgEEHvS7Pz2psMMiK2wivtt__9aLnzyg-sfE0lgVUV1-WnbZLNeNFOllPPQobLGU6shhT9t0Y1610xPWF1AMS_uUin6C1ZmdH689ZGggNPaFu_iehnM22AiKfRza93ReJJSIds6s6BGEuGzYGaSP8VhyFl9gQJlzoNzW9fxd2eqxVoMX7d0JBvfv0n7SecJlFar8GvfiBv05DYRPFU35n5vykbzCG4p3JKFA6ImsAH9rJN0jkta-lx8D1dgIzprpBnz0PugWoIBTqs5bO5h9p_ShLAEjRwwCs9uNrEkfpmDxeGn610s3g7FHpzCtJeJJs8NXFQ", "e": "AQAB"}"#;

const JWK_2: &str = r#"{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "idp-1", "n": "v4mTNy6do1-Yek-YX_17QfVcNqkshB14LwzIe3Y54TiZwZu4NN--YPsbb9U9jLiYKJrGlOVj5zlKtfIpmBZUD47Lb1klPCsOySmJnZDIY5cjkCRXx_wo9gb6EBNxxOu47lTirMm19BWpgDz4OP3vEQzM-RLylTTZ3x_xKO9a6m9H1-ewQsU3ELHGVDpmsovV48jKt-XVHhhYUxgGyE1a3yPue07gA6V26LZY3iSPBNJJwIM_4cxoLnJdN7ANfVBJPpObR1QWrjXBRv-xx-wtw1LFg8Z0TK02eZtfA7BcJBO7Pk0_6_X3GYd9pLda0OQsFgn-LsmVTiTrDESS1-lGgQ", "e": "AQAB"}"#;


/// A fixture issuer: its discovery document and one key.
struct Fixture {
    issuer: &'static str,
    jwk: &'static str,
}

#[async_trait]
impl JwksFetcher for Fixture {
    async fn fetch(&self, url: &url::Url) -> Result<FetchedDocument, FetchError> {
        let base = self.issuer.trim_end_matches('/');
        match url.path() {
            "/.well-known/openid-configuration" => Ok(FetchedDocument {
                body: json!({ "issuer": self.issuer, "jwks_uri": format!("{base}/jwks.json") }).to_string(),
                cache_control: None,
            }),
            "/jwks.json" => Ok(FetchedDocument {
                body: format!(r#"{{"keys": [{}]}}"#, self.jwk),
                cache_control: None,
            }),
            other => Err(FetchError(format!("no route {other}"))),
        }
    }
}

fn adapter_auth0() -> OidcAdapter {
    let config = OidcAdapter::config(AUTH0, AUTH0_AUD).unwrap();
    let fetcher = Arc::new(Fixture { issuer: AUTH0, jwk: JWK_1 });
    OidcAdapter::auth0_with(OidcValidator::with_fetcher(config, fetcher), Some(ROLES_CLAIM))
}

fn adapter_idp() -> OidcAdapter {
    let config = OidcAdapter::config(IDP, IDP_AUD).unwrap();
    let fetcher = Arc::new(Fixture { issuer: IDP, jwk: JWK_2 });
    OidcAdapter::plexus_idp_with(OidcValidator::with_fetcher(config, fetcher))
}

fn boundary() -> Carriers {
    Carriers::cookie_and_bearer(
        AuthenticatorChain::new()
            .with(Arc::new(adapter_auth0()))
            .with(Arc::new(adapter_idp()))
            .with(Arc::new(Nip98Adapter::new([SERVICE]).unwrap())),
    )
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn mint(kid: &str, pem: &str, claims: serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    encode(&header, &claims, &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap()).unwrap()
}

fn auth0_token(aud: &str) -> String {
    mint("acme-1", KEY_1_PEM, json!({
        "iss": AUTH0, "aud": aud, "sub": "auth0|64f1ab", "exp": now() + 600, "iat": now() - 5,
        "nickname": "ada", "email": "ada@example.com", ROLES_CLAIM: ["admin", "editor"],
    }))
}

const ALICE: &str = "c952acd3-60aa-4534-b2e3-83634591fee1";

fn idp_token() -> String {
    mint("idp-1", KEY_2_PEM, json!({
        "iss": IDP, "aud": IDP_AUD, "sub": ALICE, "exp": now() + 600, "iat": now() - 5,
        "username": "alice", "roles": ["user"], "org_id": "acme",
    }))
}

fn nip98(keys: &Keys, u: &str, method: &str, at: u64) -> String {
    let tag = |t: [&str; 2]| Tag::parse(t).unwrap();
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags([tag(["u", u]), tag(["method", method])])
        .custom_created_at(nostr::types::Timestamp::from_secs(at))
        .finalize(keys)
        .unwrap();
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&event).unwrap())
}

fn meta<'a>(ctx: &'a AuthContext, key: &str) -> &'a str {
    ctx.metadata.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

#[tokio::test]
async fn an_auth0_token_becomes_an_oidc_principal() {
    let ctx = boundary().validate(&auth0_token(AUTH0_AUD)).await.expect("admitted");
    assert_eq!(ctx.principal().unwrap().to_string(), "oidc:auth0/auth0|64f1ab");
    assert_eq!(ctx.roles, vec!["admin", "editor"]);
    assert_eq!(meta(&ctx, "name"), "ada");
    assert_eq!(meta(&ctx, "provider"), "auth0");
    assert!(ctx.is_authenticated());
}

#[tokio::test]
async fn a_plexus_idp_token_becomes_an_idp_principal() {
    let ctx = boundary().validate(&idp_token()).await.expect("admitted");
    assert_eq!(ctx.principal().unwrap().to_string(), format!("idp:{ALICE}"));
    assert_eq!(ctx.user_id, ALICE);
    assert_eq!(ctx.roles, vec!["user"]);
    assert_eq!(meta(&ctx, "name"), "alice");
    assert_eq!(meta(&ctx, "provider"), "plexus-idp");
    assert_eq!(ctx.tenant_id().unwrap().as_str(), "acme");
    assert!(ctx.is_authenticated());
}

#[tokio::test]
async fn the_access_token_cookie_reaches_its_adapter() {
    let header = format!("theme=dark; access_token={}", auth0_token(AUTH0_AUD));
    let ctx = boundary().validate(&header).await.expect("admitted");
    assert_eq!(meta(&ctx, "provider"), "auth0");
}

#[tokio::test]
async fn a_token_from_an_unconfigured_issuer_is_nobody() {
    let foreign = mint("acme-1", KEY_1_PEM, json!({
        "iss": "https://evil.example/", "aud": AUTH0_AUD, "sub": "x", "exp": now() + 600, "iat": now() - 5,
    }));
    assert!(boundary().validate(&foreign).await.is_none());
}

#[tokio::test]
async fn a_claimed_token_that_fails_is_refused() {
    let b = boundary();
    assert!(b.validate(&auth0_token("https://other.example")).await.is_none(), "wrong audience");
    let mut t = auth0_token(AUTH0_AUD);
    t.push('x');
    assert!(b.validate(&t).await.is_none(), "tampered signature");
}

#[tokio::test]
async fn a_nostr_event_becomes_a_nostr_principal_once() {
    let keys = Keys::generate();
    let b = boundary();
    let cookie = format!("nostr={}", nip98(&keys, SERVICE, "get", now() as u64));
    let ctx = b.validate(&cookie).await.expect("admitted");
    assert_eq!(ctx.principal().unwrap().to_string(), format!("nostr:{}", keys.public_key().to_hex()));
    assert_eq!(meta(&ctx, "name"), keys.public_key().to_bech32().unwrap());
    assert_eq!(meta(&ctx, "provider"), "nostr");
    assert!(ctx.is_authenticated());
    assert!(b.validate(&cookie).await.is_none(), "an event works once");
}

#[tokio::test]
async fn a_nostr_event_for_elsewhere_or_old_or_not_get_is_refused() {
    let keys = Keys::generate();
    let b = boundary();
    let t = now() as u64;
    assert!(b.validate(&nip98(&keys, "ws://127.0.0.1:9999/", "GET", t)).await.is_none(), "other service");
    assert!(b.validate(&nip98(&keys, SERVICE, "GET", t - 300)).await.is_none(), "stale");
    assert!(b.validate(&nip98(&keys, SERVICE, "POST", t)).await.is_none(), "not GET");
    assert!(b.validate(&nip98(&keys, SERVICE, "GET", t)).await.is_some(), "the same key, done right");
}

#[test]
fn an_oidc_principal_has_one_rendering() {
    let p = Principal::oidc("auth0", "auth0|64f1ab").unwrap();
    assert_eq!(p.issuer(), Issuer::Oidc);
    assert_eq!(p.to_string(), "oidc:auth0/auth0|64f1ab");
    assert_eq!(p.to_string().parse::<Principal>().unwrap(), p);
    let colon = Principal::oidc("logto", "urn:user:7").unwrap();
    assert_eq!(colon.to_string(), "oidc:logto/urn%3Auser%3A7");
    assert_eq!(colon.to_string().parse::<Principal>().unwrap(), colon);
    assert!(Principal::oidc("Auth0", "x").is_err(), "provider names are lowercase");
    assert!("oidc:auth0".parse::<Principal>().is_err(), "no provider/subject split");
    assert!(format!("idp:{ALICE}").parse::<Principal>().is_ok(), "idp still parses");
}
