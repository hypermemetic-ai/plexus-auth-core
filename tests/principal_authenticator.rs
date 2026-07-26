//! PLX-82 acceptance tests, exercised through the crate's *public* surface.
//!
//! The unit tests inside `src/identity/` cover each piece; this file asserts
//! the three properties the ticket names, from outside the crate, the way a
//! consumer would reach them.

use std::sync::Arc;

use async_trait::async_trait;
use plexus_auth_core::identity::{
    ApiKeyAuthenticator, Authenticator, AuthenticatorChain, AuthnRejection, BearerJwtAuthenticator,
    CookieAuthenticator, CredentialClass, CredentialLink, InMemoryCredentialLink, Issuer,
    LinkedCredential, Presentation, Principal, TokenVerifier, VerifiedClaims,
};
use plexus_auth_core::{AuthContext, PRINCIPAL_CLAIM};
use serde_json::{json, Value};

const ALICE: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const PUBKEY: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

/// Stands in for plexus-idp's RS256 validation: the same shape (verify, then
/// report subject + roles + claims), without the key material.
struct StubIdpVerifier;

#[async_trait]
impl TokenVerifier for StubIdpVerifier {
    fn issuer(&self) -> Issuer {
        Issuer::Idp
    }
    async fn verify(&self, token: &str) -> Result<VerifiedClaims, AuthnRejection> {
        match token {
            "valid" => Ok(VerifiedClaims {
                subject: ALICE.to_string(),
                roles: vec!["user".into(), "admin".into()],
                claims: json!({"org_id": "acme", "username": "alice"}),
            }),
            "expired" => Err(AuthnRejection::Expired),
            "" => Err(AuthnRejection::Malformed("empty token".into())),
            _ => Err(AuthnRejection::SignatureInvalid),
        }
    }
}

fn bearer_authenticator() -> Arc<dyn Authenticator> {
    Arc::new(BearerJwtAuthenticator::new("idp-bearer", StubIdpVerifier))
}

async fn linked_store() -> Arc<InMemoryCredentialLink> {
    let store = InMemoryCredentialLink::shared();
    let alice: Principal = format!("idp:{ALICE}").parse().unwrap();
    store
        .link(
            LinkedCredential::new(CredentialClass::ApiKey, "sha256-of-key", alice.clone())
                .with_roles(vec!["service".into()])
                .with_claims(json!({"org_id": "acme"})),
        )
        .await
        .unwrap();
    store
        .link(LinkedCredential::new(
            CredentialClass::Password,
            "alice",
            alice.clone(),
        ))
        .await
        .unwrap();
    store
        .link(LinkedCredential::new(
            CredentialClass::NostrKey,
            PUBKEY,
            alice,
        ))
        .await
        .unwrap();
    store
}

// ── AC1: an Authenticator impl per credential kind ─────────────────────

#[tokio::test]
async fn ac1_bearer_produces_a_verified_principal_and_typed_rejections() {
    let a = bearer_authenticator();
    assert_eq!(a.name(), "idp-bearer");

    let ok = a
        .authenticate(&Presentation::Bearer {
            token: "valid".into(),
        })
        .await
        .unwrap();
    assert_eq!(ok.principal().to_string(), format!("idp:{ALICE}"));
    assert_eq!(ok.principal().issuer(), Issuer::Idp);
    assert_eq!(ok.roles(), ["user", "admin"]);

    for (token, expected) in [
        ("expired", AuthnRejection::Expired),
        ("forged", AuthnRejection::SignatureInvalid),
    ] {
        assert_eq!(
            a.authenticate(&Presentation::Bearer {
                token: token.into()
            })
            .await
            .unwrap_err(),
            expected,
            "token {token}"
        );
    }
    assert!(matches!(
        a.authenticate(&Presentation::Bearer { token: "".into() })
            .await
            .unwrap_err(),
        AuthnRejection::Malformed(_)
    ));
}

#[tokio::test]
async fn ac1_api_key_produces_a_verified_principal_and_typed_rejections() {
    let store = linked_store().await;
    let a = ApiKeyAuthenticator::new(
        "apikey",
        store,
        Arc::new(|raw: &str| format!("sha256-of-{raw}")),
    );

    let ok = a
        .authenticate(&Presentation::ApiKey { key: "key".into() })
        .await
        .unwrap();
    assert_eq!(ok.principal().to_string(), format!("idp:{ALICE}"));
    assert_eq!(ok.roles(), ["service"]);

    assert_eq!(
        a.authenticate(&Presentation::ApiKey {
            key: "never-issued".into()
        })
        .await
        .unwrap_err(),
        AuthnRejection::UnknownCredential
    );
    assert!(matches!(
        a.authenticate(&Presentation::ApiKey { key: "".into() })
            .await
            .unwrap_err(),
        AuthnRejection::Malformed(_)
    ));
}

#[tokio::test]
async fn ac1_cookie_produces_a_verified_principal_and_typed_rejections() {
    let a = CookieAuthenticator::new("idp-cookie", "access_token", bearer_authenticator());

    let ok = a
        .authenticate(&Presentation::Cookie {
            header: "theme=dark; access_token=valid; last=1".into(),
        })
        .await
        .unwrap();
    assert_eq!(ok.principal().to_string(), format!("idp:{ALICE}"));

    // No such cookie -> malformed, not "unauthenticated by signature".
    assert!(matches!(
        a.authenticate(&Presentation::Cookie {
            header: "theme=dark".into()
        })
        .await
        .unwrap_err(),
        AuthnRejection::Malformed(_)
    ));
    // Expired token inside the cookie surfaces the inner reason unchanged.
    assert_eq!(
        a.authenticate(&Presentation::Cookie {
            header: "access_token=expired".into()
        })
        .await
        .unwrap_err(),
        AuthnRejection::Expired
    );
    // An empty cookie value is malformed rather than a signature failure.
    assert!(matches!(
        a.authenticate(&Presentation::Cookie {
            header: "access_token=".into()
        })
        .await
        .unwrap_err(),
        AuthnRejection::Malformed(_)
    ));
}

#[tokio::test]
async fn ac1_a_chain_of_all_three_routes_each_credential_kind() {
    let store = linked_store().await;
    let chain = AuthenticatorChain::new()
        .with(Arc::new(CookieAuthenticator::new(
            "idp-cookie",
            "access_token",
            bearer_authenticator(),
        )))
        .with(bearer_authenticator())
        .with(Arc::new(ApiKeyAuthenticator::new(
            "apikey",
            store,
            Arc::new(|raw: &str| format!("sha256-of-{raw}")),
        )));

    assert_eq!(chain.names(), ["idp-cookie", "idp-bearer", "apikey"]);

    // Cookie carrier.
    assert!(chain
        .authenticate(&Presentation::Cookie {
            header: "access_token=valid".into()
        })
        .await
        .is_ok());
    // Bearer carrier, JWT.
    assert!(chain
        .authenticate(&Presentation::Bearer {
            token: "valid".into()
        })
        .await
        .is_ok());
    // Bearer carrier, API key: the JWT authenticator claims it and fails with
    // SignatureInvalid, so the chain short-circuits rather than falling
    // through. Presented as an ApiKey, it resolves.
    assert!(chain
        .authenticate(&Presentation::ApiKey { key: "key".into() })
        .await
        .is_ok());
}

// ── AC2: principal and legacy user_id cannot diverge ───────────────────

#[tokio::test]
async fn ac2_idp_token_yields_principal_equal_to_idp_colon_user_id() {
    let ok = bearer_authenticator()
        .authenticate(&Presentation::Bearer {
            token: "valid".into(),
        })
        .await
        .unwrap();
    let ctx = ok.into_auth_context();

    // The legacy field is byte-identical to what plexus-idp writes today.
    assert_eq!(ctx.user_id, ALICE);

    // And the principal is exactly `idp:<user_id>`, by both available routes.
    let from_ctx = ctx.principal().expect("context must name a principal");
    let from_user_id: Principal = format!("idp:{}", ctx.user_id).parse().unwrap();
    assert_eq!(from_ctx, from_user_id);
    assert_eq!(from_ctx.subject(), ctx.user_id);
    assert_eq!(from_ctx.issuer(), Issuer::Idp);

    // Verified claims survived the projection.
    assert_eq!(ctx.get_metadata_string("org_id").as_deref(), Some("acme"));
    assert!(ctx.has_role("admin"));
}

#[test]
fn ac2_the_two_routes_to_a_principal_agree_for_every_idp_context() {
    // Route A: a context built by an *old* code path — no stamp, just a
    // user_id. Route B: the same identity stamped by an authenticator.
    let legacy = AuthContext::new(
        ALICE.to_string(),
        "sess-1".to_string(),
        vec!["user".into()],
        json!({"org_id": "acme"}),
    );
    let principal: Principal = format!("idp:{ALICE}").parse().unwrap();
    let stamped = AuthContext::for_principal(
        &principal,
        "sess-1",
        vec!["user".into()],
        json!({"org_id": "acme"}),
    );

    assert_eq!(legacy.principal(), stamped.principal());
    assert_eq!(legacy.user_id, stamped.user_id);
    assert_eq!(legacy.principal(), Some(principal));
}

#[test]
fn ac2_contexts_without_a_nameable_subject_return_none() {
    assert_eq!(AuthContext::anonymous().principal(), None);
    // A non-idp user_id is not silently claimed for the idp namespace.
    let foreign = AuthContext::new(
        "auth0|abc123".to_string(),
        String::new(),
        vec![],
        Value::Null,
    );
    assert_eq!(foreign.principal(), None);
    // A corrupt stamp is None, not a fallback to the user_id — answering
    // from user_id would answer a different question than the stamp asked.
    let corrupt = AuthContext::new(
        ALICE.to_string(),
        String::new(),
        vec![],
        json!({ PRINCIPAL_CLAIM: "ldap:someone" }),
    );
    assert_eq!(corrupt.principal(), None);
}

#[test]
fn ac2_non_idp_principals_do_not_collide_in_the_legacy_user_id_field() {
    let nostr: Principal = format!("nostr:{PUBKEY}").parse().unwrap();
    let ctx = AuthContext::for_principal(&nostr, "", vec![], Value::Null);

    // A self-sovereign subject keeps its namespace in `user_id`, so it can
    // never be confused with an idp UUID by code that still reads that field.
    assert_eq!(ctx.user_id, format!("nostr:{PUBKEY}"));
    assert_eq!(ctx.principal(), Some(nostr));
    assert!(ctx.user_id != PUBKEY);
}

#[test]
fn ac2_additive_the_pre_existing_authcontext_api_is_unchanged() {
    // Everything a pre-PLX-82 caller could do still works, including
    // constructing by exhaustive struct literal — the reason `principal` is
    // a derived accessor and not a sixth field.
    let ctx = AuthContext {
        user_id: ALICE.to_string(),
        session_id: "s".to_string(),
        roles: vec!["user".into()],
        metadata: json!({"tenant_id": "acme"}),
    };
    assert!(ctx.is_authenticated());
    assert!(ctx.has_role("user"));
    assert_eq!(ctx.tenant().as_deref(), Some("acme"));
    assert_eq!(
        ctx.tenant_id().map(|t| t.as_str().to_string()),
        Some("acme".to_string())
    );
    // ...and it still names a principal, without having been told one.
    assert_eq!(ctx.principal().map(|p| p.to_string()), Some(format!("idp:{ALICE}")));

    // The wire shape is unchanged: no new required field.
    let from_wire: AuthContext = serde_json::from_str(
        r#"{"user_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","session_id":"s","roles":[],"metadata":null}"#,
    )
    .expect("pre-PLX-82 documents must still deserialize");
    assert_eq!(from_wire.principal().map(|p| p.to_string()), Some(format!("idp:{ALICE}")));
}

// ── AC3: one principal, many credentials ───────────────────────────────

#[tokio::test]
async fn ac3_two_different_credentials_resolve_to_one_subject() {
    let store = linked_store().await;
    let alice: Principal = format!("idp:{ALICE}").parse().unwrap();

    // A password login and a nostr key: entirely different proof models,
    // entirely different locators, one human.
    let via_password = store
        .resolve(CredentialClass::Password, "alice")
        .await
        .unwrap()
        .expect("password credential is linked");
    let via_nostr = store
        .resolve(CredentialClass::NostrKey, PUBKEY)
        .await
        .unwrap()
        .expect("nostr credential is linked");
    let via_apikey = store
        .resolve(CredentialClass::ApiKey, "sha256-of-key")
        .await
        .unwrap()
        .expect("api key is linked");

    assert_eq!(via_password.principal(), &alice);
    assert_eq!(via_nostr.principal(), &alice);
    assert_eq!(via_apikey.principal(), &alice);

    let all = store.credentials_for(&alice).await.unwrap();
    assert_eq!(all.len(), 3, "one principal, three credentials");
}

#[tokio::test]
async fn ac3_the_api_key_authenticator_reads_through_the_same_link_store() {
    // The store is not a parallel universe: authenticating with the API key
    // yields the very principal the password login resolves to.
    let store = linked_store().await;
    let a = ApiKeyAuthenticator::plaintext("apikey", store.clone());

    let authed = a
        .authenticate(&Presentation::ApiKey {
            key: "sha256-of-key".into(),
        })
        .await
        .unwrap();
    let via_password = store
        .resolve(CredentialClass::Password, "alice")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(authed.principal(), via_password.principal());
}

// The corresponding "a forwarding boundary that drops the verified user must
// also drop the principal stamp" test lives in `src/auth.rs`'s unit tests: it
// needs a sealed caller-stamp `Principal`, which by design has no constructor
// reachable from an integration test.
