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
use plexus_auth_core::identity::{Authenticator, AuthenticatorChain, Issuer, Presentation, Principal};
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
        // An issuer may have a path (WorkOS's per-client issuer does).
        let path = url.path().strip_prefix(url::Url::parse(base).unwrap().path().trim_end_matches('/')).unwrap_or("");
        match path {
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

#[tokio::test]
async fn a_login_endpoint_takes_post_events_and_refuses_get_ones() {
    let url = "http://127.0.0.1:4451/login/nostr";
    let adapter = Nip98Adapter::new([url]).unwrap().for_method("POST");
    let keys = Keys::generate();
    let t = now() as u64;
    let bearer = |m: &str| Presentation::Bearer { token: nip98(&keys, url, m, t) };
    use plexus_auth_core::identity::Authenticator;
    assert!(adapter.authenticate(&bearer("GET")).await.is_err(), "GET is not this endpoint's method");
    assert!(adapter.authenticate(&bearer("post")).await.is_ok(), "POST, in any case");
}

#[tokio::test]
async fn an_oidc_identity_carries_its_token_s_expiry() {
    let ctx = boundary().validate(&idp_token()).await.expect("admitted");
    let exp = ctx.metadata["expires_at"].as_i64().expect("expires_at");
    assert!((exp - (now() + 600)).abs() <= 2, "{exp}");
}

// ── IDENTITY-30: WorkOS ────────────────────────────────────────────────
//
// Shaped like the access token a real staging sign-in returned
// (2026-10-09): the issuer is per client, there is no `aud`, the client is
// named in `client_id`, and the token lives five minutes.

const WORKOS_BASE: &str = "http://127.0.0.1:4490";
const WORKOS_CLIENT: &str = "client_01M4GRE0HND6SKGPV780GPTYDX";
const WORKOS_OTHER: &str = "client_01OTHERCLIENT0000000000000";

fn workos_issuer(client: &str) -> String {
    format!("{WORKOS_BASE}/user_management/{client}")
}

fn adapter_workos() -> OidcAdapter {
    let config = OidcAdapter::workos_config(WORKOS_CLIENT, Some(WORKOS_BASE)).unwrap();
    let issuer: &'static str = Box::leak(workos_issuer(WORKOS_CLIENT).into_boxed_str());
    let fetcher = Arc::new(Fixture { issuer, jwk: JWK_1 });
    OidcAdapter::workos_with(OidcValidator::with_fetcher(config, fetcher))
}

fn workos_token(iss: &str, client_id: Option<&str>) -> String {
    let mut claims = json!({
        "iss": iss, "sub": "user_01M4GS8A1YTZ8SD864JTME6VME", "sid": "session_01M4GSFNF96RHC4Y9GQ04YYTJ8",
        "jti": "01M4GSFNJ3STHBMC80JZD4XWWC", "auth_time": now() - 5, "org_id": "org_01M4GRE0C2WPYY2VDRPC6BXZWC",
        "role": "member", "roles": ["member"], "permissions": [], "exp": now() + 300, "iat": now() - 5,
    });
    if let Some(c) = client_id {
        claims["client_id"] = json!(c);
    }
    mint("acme-1", KEY_1_PEM, claims)
}

#[tokio::test]
async fn a_workos_token_becomes_a_workos_principal() {
    let ctx = adapter_workos()
        .authenticate(&Presentation::Bearer {
            token: workos_token(&workos_issuer(WORKOS_CLIENT), Some(WORKOS_CLIENT)),
        })
        .await
        .expect("admitted")
        .into_auth_context();
    assert_eq!(ctx.principal().unwrap().to_string(), "oidc:workos/user_01M4GS8A1YTZ8SD864JTME6VME");
    assert_eq!(ctx.roles, vec!["member"]);
    assert_eq!(ctx.session_id, "session_01M4GSFNF96RHC4Y9GQ04YYTJ8", "the WorkOS session, for signing out");
    assert_eq!(ctx.tenant_id().unwrap().as_str(), "org_01M4GRE0C2WPYY2VDRPC6BXZWC");
    assert_eq!(meta(&ctx, "provider"), "workos");
    assert_eq!(meta(&ctx, "name"), "user_01M4GS8A1YTZ8SD864JTME6VME", "the token names nobody");
}

#[tokio::test]
async fn a_workos_token_for_another_client_or_none_is_refused() {
    let a = adapter_workos();
    let present = |token: String| Presentation::Bearer { token };
    // this client's issuer, another client named: refused, though signed
    let other = a.authenticate(&present(workos_token(&workos_issuer(WORKOS_CLIENT), Some(WORKOS_OTHER)))).await;
    assert!(other.is_err(), "another client's token");
    // no client named at all
    let none = a.authenticate(&present(workos_token(&workos_issuer(WORKOS_CLIENT), None))).await;
    assert!(none.is_err(), "a token naming no client");
    // another client's issuer: not this adapter's to claim
    let p = present(workos_token(&workos_issuer(WORKOS_OTHER), Some(WORKOS_OTHER)));
    assert!(!a.accepts(&p), "another client's issuer is someone else's token");
}

#[test]
fn the_workos_issuer_is_per_client_on_the_api() {
    let c = OidcAdapter::workos_config(WORKOS_CLIENT, None).unwrap();
    assert_eq!(c.issuer().as_url().as_str(), format!("https://api.workos.com/user_management/{WORKOS_CLIENT}"));
    assert_eq!(c.audience().as_str(), WORKOS_CLIENT);
    assert_eq!(c.audience_claim(), plexus_auth_core::oidc::AudienceClaim::ClientId);
}

// ── IDENTITY-27 ────────────────────────────────────────────────────────

fn nip98_with(keys: &Keys, u: &str, method: &str, payload: Option<&str>) -> String {
    let tag = |t: &[&str]| Tag::parse(t.iter().copied()).unwrap();
    let mut tags = vec![tag(&["u", u]), tag(&["method", method])];
    if let Some(p) = payload {
        tags.push(tag(&["payload", p]));
    }
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .custom_created_at(nostr::types::Timestamp::from_secs(now() as u64))
        .finalize(keys)
        .unwrap();
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&event).unwrap())
}

#[tokio::test]
async fn a_nostr_identity_carries_an_expiry() {
    use plexus_auth_core::adapters::NIP98_DEFAULT_LIFETIME_SECS;
    let keys = Keys::generate();
    let ctx = boundary().validate(&nip98(&keys, SERVICE, "GET", now() as u64)).await.expect("admitted");
    let exp = ctx.metadata["expires_at"].as_i64().expect("expires_at");
    assert!((exp - (now() + NIP98_DEFAULT_LIFETIME_SECS as i64)).abs() <= 2, "{exp}");

    let short = Nip98Adapter::new([SERVICE]).unwrap().with_lifetime(300);
    let a = short
        .authenticate(&Presentation::Bearer { token: nip98(&keys, SERVICE, "GET", now() as u64) })
        .await
        .expect("admitted");
    let exp = a.into_auth_context().metadata["expires_at"].as_i64().unwrap();
    assert!((exp - (now() + 300)).abs() <= 2, "{exp}");
}

#[tokio::test]
async fn a_nostr_payload_tag_binds_the_body() {
    use sha2::Digest;
    let url = "http://127.0.0.1:4451/login/nostr";
    let adapter = Nip98Adapter::new([url]).unwrap().for_method("POST");
    let keys = Keys::generate();
    let body = br#"{"next":"/"}"#;
    let hash: String = sha2::Sha256::digest(body).iter().map(|b| format!("{b:02x}")).collect();
    let empty: String = sha2::Sha256::digest(b"").iter().map(|b| format!("{b:02x}")).collect();

    let t = nip98_with(&keys, url, "POST", Some(&hash));
    assert!(adapter.authenticate_request(&t, body).await.is_ok(), "the body it names");
    let t = nip98_with(&keys, url, "POST", Some(&hash));
    assert!(adapter.authenticate_request(&t, b"{\"next\":\"/evil\"}").await.is_err(), "another body");
    let t = nip98_with(&keys, url, "POST", None);
    assert!(adapter.authenticate_request(&t, body).await.is_err(), "a body needs a payload tag");
    let t = nip98_with(&keys, url, "POST", None);
    assert!(adapter.authenticate_request(&t, b"").await.is_ok(), "no body, no tag");
    let t = nip98_with(&keys, url, "POST", Some(&empty));
    assert!(adapter.authenticate_request(&t, b"").await.is_ok(), "no body, the empty body's hash");
}

#[tokio::test]
async fn bearer_only_carriers_read_no_cookie() {
    let chain = || {
        AuthenticatorChain::new()
            .with(Arc::new(adapter_auth0()))
            .with(Arc::new(Nip98Adapter::new([SERVICE]).unwrap()))
    };
    let b = Carriers::bearer_only(chain());
    // A cookie another port of this host planted is not a credential…
    let planted = format!("access_token={}", auth0_token(AUTH0_AUD));
    assert!(b.validate(&planted).await.is_none(), "access_token cookie");
    assert!(b.validate(&format!("theme=dark; {planted}")).await.is_none(), "among others");
    let keys = Keys::generate();
    let nostr = format!("nostr={}", nip98(&keys, SERVICE, "GET", now() as u64));
    assert!(b.validate(&nostr).await.is_none(), "nostr cookie");
    // …and never reaches an adapter: the same event still works once, as a bearer.
    let event = nostr.strip_prefix("nostr=").unwrap();
    assert!(b.validate(event).await.is_some(), "the event, as the bearer value");
    // The bearer value is.
    let ctx = b.validate(&auth0_token(AUTH0_AUD)).await.expect("bearer admitted");
    assert_eq!(meta(&ctx, "provider"), "auth0");
    // The cookie carriers still read it.
    assert!(Carriers::cookie_and_bearer(chain()).validate(&planted).await.is_some());
}

#[test]
fn two_providers_of_one_name_are_refused() {
    use plexus_auth_core::adapters::AdapterError;
    let twice = AuthenticatorChain::new()
        .with(Arc::new(adapter_auth0()))
        .with(Arc::new(adapter_auth0()));
    assert!(matches!(Carriers::try_cookie_and_bearer(twice.clone()), Err(AdapterError::DuplicateProvider(n)) if n == "auth0"));
    assert!(matches!(Carriers::try_bearer_only(twice), Err(AdapterError::DuplicateProvider(_))));
    let once = AuthenticatorChain::new().try_with(Arc::new(adapter_auth0())).unwrap();
    assert_eq!(once.clone().try_with(Arc::new(adapter_auth0())).unwrap_err(), "auth0");
    let both = once.try_with(Arc::new(adapter_idp())).unwrap();
    assert!(Carriers::try_bearer_only(both).is_ok());
}

// ── IDENTITY-41: an agent's key proof ──────────────────────────────────

mod key_proof {
    use super::*;
    use plexus_auth_core::adapters::{
        key_principal, key_proof_message, sign_key_proof, valid_agent_id, KeyProofAdapter, KEY_PROOF_PREFIX,
    };
    use plexus_auth_core::identity::AuthnRejection;
    use serde_json::Value;

    const AUD: &str = "ws://127.0.0.1:4460";
    const TS: i64 = 1_791_600_000;

    /// The fixed vector's seed: bytes 0x01, 0x02, …, 0x20.
    fn seed() -> [u8; 32] {
        std::array::from_fn(|i| i as u8 + 1)
    }

    /// The fixed vector's proof, exactly as it goes on the wire — the
    /// synapse side (IDENTITY-43) must produce these same bytes from the
    /// same inputs: seed 0x01..0x20, aud `ws://127.0.0.1:4460`, agent
    /// `worker-3`, nonce 32 bytes of 0x07, ts 1791600000.
    const VECTOR: &str = "plexus-key.eyJ2IjoxLCJrZXkiOiI3OWI1NTYyZThmZTY1NGY5NDA3OGIxMTJlOGE5OGJhNzkwMWY4NTNhZTY5NWJlZDdlMGUzOTEwYmFkMDQ5NjY0IiwiYXVkIjoid3M6Ly8xMjcuMC4wLjE6NDQ2MCIsImFnZW50Ijoid29ya2VyLTMiLCJub25jZSI6IkJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2MiLCJ0cyI6MTc5MTYwMDAwMCwic2lnIjoiSlJxSGx6VEd2WGZubm8zQWlsMWhudU9wZ2J6SzlyNFZPa0l6OHNRbmpkVzZwWlk4S1h5YlR4QlBBcmdaclFkeFR1M3NvaWtwSkxRMURSaDN3SVFLQVEifQ";

    fn adapter_at(now: i64) -> KeyProofAdapter {
        KeyProofAdapter::new([AUD, "ws://localhost:4460"]).unwrap().with_clock(move || now)
    }

    fn bearer(token: String) -> Presentation {
        Presentation::Bearer { token }
    }

    /// A proof's JSON, to tamper with.
    fn json_of(proof: &str) -> Value {
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(proof.strip_prefix(KEY_PROOF_PREFIX).unwrap()).unwrap();
        serde_json::from_slice(&b).unwrap()
    }

    fn proof_of(json: &Value) -> String {
        format!("{KEY_PROOF_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(json).unwrap()))
    }

    #[tokio::test]
    async fn the_fixed_vector() {
        let proof = sign_key_proof(&seed(), AUD, "worker-3", &[7u8; 32], TS);
        println!("IDENTITY-41 fixed vector proof: {proof}");
        let json = json_of(&proof);
        let wire = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(proof.strip_prefix(KEY_PROOF_PREFIX).unwrap()).unwrap();
        println!("IDENTITY-41 fixed vector JSON: {}", String::from_utf8(wire.clone()).unwrap());
        assert_eq!(
            String::from_utf8(wire).unwrap(),
            r#"{"v":1,"key":"79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664","aud":"ws://127.0.0.1:4460","agent":"worker-3","nonce":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","ts":1791600000,"sig":"JRqHlzTGvXfnno3Ail1hnuOpgbzK9r4VOkIz8sQnjdW6pZY8KXybTxBPArgZrQdxTu3soikpJLQ1DRh3wIQKAQ"}"#,
            "the JSON, in the wire's field order (checked against an independent Ed25519: Python's cryptography)"
        );
        println!("IDENTITY-41 fixed vector message: {:?}", key_proof_message(AUD, "worker-3", json["nonce"].as_str().unwrap(), TS));
        assert_eq!(proof, VECTOR, "the wire bytes of the fixed vector");

        let ok = adapter_at(TS).authenticate(&bearer(proof)).await.unwrap();
        let key = json["key"].as_str().unwrap();
        assert_eq!(ok.principal().to_string(), format!("key:{key}"));
        assert_eq!(ok.principal().issuer(), Issuer::Key);
        assert_eq!(ok.claims()["agent"], "worker-3");
        assert_eq!(ok.claims()["name"], "worker-3");
        assert_eq!(ok.claims()["provider"], "key");
        assert_eq!(ok.claims()["auth_method"], "key");
        assert_eq!(ok.claims()["expires_at"], TS + 300);
        assert_eq!(json["nonce"], "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc");
        let keys: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys.len(), 7);
        let ctx = ok.into_auth_context();
        assert_eq!(ctx.principal().unwrap().to_string(), format!("key:{key}"));
    }

    #[tokio::test]
    async fn a_fresh_proof_opens_once_through_the_carriers() {
        let now = system_now();
        let carriers = Carriers::cookie_and_bearer(AuthenticatorChain::new().with(Arc::new(
            KeyProofAdapter::new([AUD]).unwrap(),
        )));
        let proof = sign_key_proof(&seed(), AUD, "worker-3", &[1u8; 32], now);
        let ctx = carriers.validate(&proof).await.expect("bearer");
        assert_eq!(meta(&ctx, "name"), "worker-3");
        assert!(carriers.validate(&proof).await.is_none(), "replayed");
        let other = sign_key_proof(&seed(), AUD, "worker-3", &[2u8; 32], now);
        assert!(carriers.validate(&format!("theme=dark; access_token={other}")).await.is_some(), "the access_token cookie");
    }

    fn system_now() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
    }

    #[tokio::test]
    async fn refusals() {
        let a = adapter_at(TS);
        let sign = |aud: &str, agent: &str, nonce: u8, ts: i64| sign_key_proof(&seed(), aud, agent, &[nonce; 32], ts);

        // Replay: the same (key, nonce) twice.
        let once = sign(AUD, "worker-3", 9, TS);
        assert!(a.authenticate(&bearer(once.clone())).await.is_ok());
        assert!(matches!(a.authenticate(&bearer(once)).await, Err(AuthnRejection::Malformed(m)) if m.contains("already used")));

        // The window: −60 s / +30 s.
        assert!(a.authenticate(&bearer(sign(AUD, "w", 10, TS - 60))).await.is_ok());
        assert_eq!(a.authenticate(&bearer(sign(AUD, "w", 11, TS - 61))).await.unwrap_err(), AuthnRejection::Expired, "stale");
        assert!(a.authenticate(&bearer(sign(AUD, "w", 12, TS + 30))).await.is_ok());
        assert_eq!(a.authenticate(&bearer(sign(AUD, "w", 13, TS + 31))).await.unwrap_err(), AuthnRejection::Expired, "future");

        // Another server's URL; the other configured one, and a trailing slash, are this one.
        let e = a.authenticate(&bearer(sign("ws://127.0.0.1:4455", "w", 14, TS))).await.unwrap_err();
        assert!(matches!(&e, AuthnRejection::Malformed(m) if m.contains("aud")), "{e}");
        assert!(a.authenticate(&bearer(sign("ws://localhost:4460", "w", 15, TS))).await.is_ok());
        assert!(a.authenticate(&bearer(sign("ws://127.0.0.1:4460/", "w", 16, TS))).await.is_ok());

        // Signed by another key: the key named is not the signer's.
        let mut forged = json_of(&sign(AUD, "w", 17, TS));
        let other = sign_key_proof(&[42u8; 32], AUD, "w", &[17; 32], TS);
        forged["key"] = json_of(&other)["key"].clone();
        assert_eq!(a.authenticate(&bearer(proof_of(&forged))).await.unwrap_err(), AuthnRejection::SignatureInvalid);
        // A signature over another message: the agent changed after signing.
        let mut changed = json_of(&sign(AUD, "worker-3", 18, TS));
        changed["agent"] = "worker-4".into();
        assert_eq!(a.authenticate(&bearer(proof_of(&changed))).await.unwrap_err(), AuthnRejection::SignatureInvalid);
        // A forgery does not burn the nonce: the real proof still opens.
        assert!(a.authenticate(&bearer(sign(AUD, "w", 17, TS))).await.is_ok());

        // Bad agent ids.
        for agent in ["", "has space", "slash/no", "colon:no", &"a".repeat(65), "é"] {
            let e = a.authenticate(&bearer(sign(AUD, agent, 19, TS))).await.unwrap_err();
            assert!(matches!(&e, AuthnRejection::Malformed(m) if m.contains("agent")), "{agent:?}: {e}");
        }
        assert!(valid_agent_id(&"a".repeat(64)) && valid_agent_id("A.b_c-9"));

        // Shape: v, nonce length, uppercase key, padding, garbage.
        let mut v2 = json_of(&sign(AUD, "w", 20, TS));
        v2["v"] = 2.into();
        assert!(a.authenticate(&bearer(proof_of(&v2))).await.is_err());
        let mut short = json_of(&sign(AUD, "w", 21, TS));
        short["nonce"] = "BwcH".into();
        assert!(matches!(a.authenticate(&bearer(proof_of(&short))).await, Err(AuthnRejection::Malformed(m)) if m.contains("nonce")));
        let mut upper = json_of(&sign(AUD, "w", 22, TS));
        upper["key"] = upper["key"].as_str().unwrap().to_uppercase().into();
        assert!(a.authenticate(&bearer(proof_of(&upper))).await.is_err());
        let padded = format!("{}==", sign(AUD, "w", 23, TS));
        assert!(a.authenticate(&bearer(padded)).await.is_err(), "nopad only");
        assert!(matches!(a.authenticate(&bearer("plexus-key.garbage".into())).await, Err(AuthnRejection::Malformed(_))));
        // Not a proof at all: not this adapter's.
        assert!(a.authenticate(&bearer("eyJhbGciOi.x.y".into())).await.unwrap_err().is_unsupported());
    }

    #[tokio::test]
    async fn a_signed_challenge_carries_the_same_proof() {
        let a = adapter_at(TS);
        let json = json_of(&sign_key_proof(&seed(), AUD, "worker-3", &[30u8; 32], TS));
        let challenge = key_proof_message(AUD, "worker-3", json["nonce"].as_str().unwrap(), TS);
        let p = Presentation::SignedChallenge {
            scheme: "ed25519".into(),
            key_id: json["key"].as_str().unwrap().into(),
            challenge: challenge.clone(),
            signature: json["sig"].as_str().unwrap().into(),
        };
        assert_eq!(a.authenticate(&p).await.unwrap().claims()["agent"], "worker-3");
        assert!(a.authenticate(&p).await.is_err(), "once");
        let nip42 = Presentation::SignedChallenge { scheme: "nip42".into(), key_id: String::new(), challenge, signature: String::new() };
        assert!(a.authenticate(&nip42).await.unwrap_err().is_unsupported());
    }

    #[test]
    fn an_audience_is_a_websocket_url() {
        assert!(KeyProofAdapter::new(["http://127.0.0.1:4460"]).is_err());
        assert!(KeyProofAdapter::new(["not a url"]).is_err());
        let a = KeyProofAdapter::new(["ws://127.0.0.1:4460/", "ws://127.0.0.1:4460", "wss://menger.example"]).unwrap();
        assert_eq!(a.audiences(), ["ws://127.0.0.1:4460", "wss://menger.example"]);
    }

    #[test]
    fn a_key_principal_is_its_public_key_in_hex() {
        let p = key_principal(&[0xab; 32]);
        assert_eq!(p.to_string(), format!("key:{}", "ab".repeat(32)));
        assert_eq!(p.to_string().parse::<Principal>().unwrap(), p);
    }
}
