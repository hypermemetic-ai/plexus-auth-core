//! Credential linking: one [`Principal`], many credentials.
//!
//! # The problem this solves
//!
//! Today a credential *is* an identity. Register with a password and you get
//! a user row whose UUID is your identity; mint an API key and the key is
//! resolved back to that same user row only because `api_keys.user_id` is a
//! foreign key someone remembered to add. There is no general statement that
//! "these two things are the same person", and so a nostr key — which cannot
//! be a `users` row, because nobody mints it — has nowhere to attach.
//!
//! A [`CredentialLink`] store makes that statement explicit and generic: a
//! row per credential, each pointing at the [`Principal`] it authenticates.
//! A human with a password, an API key, and a nostr key is one principal with
//! three rows.
//!
//! # Schema
//!
//! The reference SQL shape (plexus-idp implements exactly this over SQLite):
//!
//! ```sql
//! CREATE TABLE credential_links (
//!     class      TEXT NOT NULL,   -- CredentialClass::as_str()
//!     locator    TEXT NOT NULL,   -- digest/username/pubkey; NEVER the secret
//!     principal  TEXT NOT NULL,   -- Principal::to_string(), e.g. idp:<uuid>
//!     roles      TEXT NOT NULL DEFAULT '[]',
//!     claims     TEXT NOT NULL DEFAULT '{}',
//!     revoked    INTEGER NOT NULL DEFAULT 0,
//!     expires_at TEXT,
//!     created_at TEXT NOT NULL,
//!     PRIMARY KEY (class, locator)
//! );
//! CREATE INDEX idx_credential_links_principal ON credential_links(principal);
//! ```
//!
//! `(class, locator)` is the primary key, which is the schema-level
//! expression of the store's central rule: **a credential resolves to exactly
//! one principal.** Two principals sharing one credential is the failure this
//! type exists to make unrepresentable.
//!
//! The reverse is unconstrained on purpose — a principal may hold any number
//! of credentials, and that is the whole point.
//!
//! # What a locator is, and is not
//!
//! A locator is a *non-secret* handle: the SHA-256 of an API key, a username,
//! a nostr pubkey. It is never the secret itself. Storing a raw API key here
//! would turn a read of this table into a full compromise, so
//! [`ApiKeyAuthenticator`](super::ApiKeyAuthenticator) digests before it
//! looks up, and this module never sees plaintext.
//!
//! # Out of scope
//!
//! Tenancy. A link says who a credential belongs to, not what they may reach.
//! Orgs, membership records, and tenant mounts are M4 (PLX-73
//! `q-tenant-isolation`, `q-user-provisioning`); `claims` carries the
//! existing `org_id` *hint* and nothing here interprets it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::principal::Principal;

/// What kind of credential a link describes.
///
/// `#[non_exhaustive]` plus a lossless `Other` variant: a deployment can
/// store a credential class this crate has never heard of without the class
/// being silently coerced into a neighbouring one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum CredentialClass {
    /// A username + password login (locator: the username).
    Password,
    /// An API key (locator: the key's digest).
    ApiKey,
    /// A nostr secp256k1 keypair (locator: the 64-hex x-only pubkey).
    NostrKey,
    /// A federated OIDC identity (locator: `<issuer>|<sub>`).
    Oidc,
    /// Anything else, kept verbatim.
    Other(String),
}

impl CredentialClass {
    /// The stored discriminant.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Password => "password",
            Self::ApiKey => "apikey",
            Self::NostrKey => "nostr_key",
            Self::Oidc => "oidc",
            Self::Other(s) => s,
        }
    }

    /// Read a stored discriminant back. Total: unknown values become
    /// [`Other`](CredentialClass::Other) rather than an error, so a row
    /// written by a newer build is still readable by an older one.
    pub fn from_stored(s: &str) -> Self {
        match s {
            "password" => Self::Password,
            "apikey" => Self::ApiKey,
            "nostr_key" => Self::NostrKey,
            "oidc" => Self::Oidc,
            other => Self::Other(other.to_string()),
        }
    }
}

impl std::fmt::Display for CredentialClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a link operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkError {
    /// `(class, locator)` is already linked to a *different* principal.
    ///
    /// Re-linking a credential to the principal it already names is a no-op,
    /// not an error; moving it to another principal is refused, because that
    /// would silently transfer an authentication path between identities.
    AlreadyLinked {
        /// The credential's class.
        class: String,
        /// The credential's locator.
        locator: String,
        /// The principal it is already bound to.
        existing: String,
    },

    /// The store could not be reached.
    Backend(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyLinked {
                class,
                locator,
                existing,
            } => write!(
                f,
                "credential `{class}:{locator}` is already linked to `{existing}`"
            ),
            Self::Backend(why) => write!(f, "credential link store error: {why}"),
        }
    }
}

impl std::error::Error for LinkError {}

/// One credential, bound to the principal it authenticates.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkedCredential {
    class: CredentialClass,
    locator: String,
    principal: Principal,
    roles: Vec<String>,
    claims: Value,
    revoked: bool,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl LinkedCredential {
    /// Bind `locator` (a non-secret handle) to `principal`.
    pub fn new(class: CredentialClass, locator: impl Into<String>, principal: Principal) -> Self {
        Self {
            class,
            locator: locator.into(),
            principal,
            roles: Vec::new(),
            claims: Value::Null,
            revoked: false,
            expires_at: None,
            created_at: Utc::now(),
        }
    }

    /// Roles this credential asserts.
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Extra claims (`org_id`, `username`, …) this credential carries.
    pub fn with_claims(mut self, claims: Value) -> Self {
        self.claims = claims;
        self
    }

    /// Give the credential a validity window.
    pub fn expiring_at(mut self, at: DateTime<Utc>) -> Self {
        self.expires_at = Some(at);
        self
    }

    /// Mark the credential withdrawn.
    pub fn revoked(mut self) -> Self {
        self.revoked = true;
        self
    }

    /// Override the creation timestamp (for stores reading rows back).
    pub fn created_at(mut self, at: DateTime<Utc>) -> Self {
        self.created_at = at;
        self
    }

    /// The credential's class.
    pub fn class(&self) -> &CredentialClass {
        &self.class
    }
    /// The non-secret handle this credential is found by.
    pub fn locator(&self) -> &str {
        &self.locator
    }
    /// The principal this credential authenticates.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }
    /// Roles asserted by this credential.
    pub fn roles(&self) -> &[String] {
        &self.roles
    }
    /// Claims carried by this credential.
    pub fn claims(&self) -> &Value {
        &self.claims
    }
    /// Has this credential been withdrawn?
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }
    /// When it stops being valid, if ever.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }
    /// When it was linked.
    pub fn created(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Is this credential past its validity window at `now`?
    ///
    /// A credential with no `expires_at` never expires — that is today's
    /// behavior for API keys with a null `expires_at` column and is
    /// preserved deliberately.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|e| e < now)
    }
}

/// A store mapping credentials to the principals they authenticate.
///
/// Object-safe and async so a SQLite, Postgres, or in-memory implementation
/// can be handed to an [`Authenticator`](super::Authenticator) as
/// `Arc<dyn CredentialLink>`.
#[async_trait]
pub trait CredentialLink: Send + Sync + 'static {
    /// Bind a credential to a principal.
    ///
    /// Idempotent when the credential is already bound to the *same*
    /// principal (metadata is refreshed); [`LinkError::AlreadyLinked`] when
    /// it is bound to a different one.
    async fn link(&self, credential: LinkedCredential) -> Result<(), LinkError>;

    /// Find the credential — and therefore the principal — behind a locator.
    ///
    /// Returns the full [`LinkedCredential`] rather than a bare
    /// [`Principal`] so the caller can enforce revocation and expiry; a
    /// store that filtered those out itself would make the two states
    /// indistinguishable from "never existed".
    async fn resolve(
        &self,
        class: CredentialClass,
        locator: &str,
    ) -> Result<Option<LinkedCredential>, LinkError>;

    /// Every credential held by a principal.
    async fn credentials_for(
        &self,
        principal: &Principal,
    ) -> Result<Vec<LinkedCredential>, LinkError>;

    /// Remove a link. Returns whether a row was removed.
    async fn unlink(&self, class: CredentialClass, locator: &str) -> Result<bool, LinkError>;
}

/// In-memory [`CredentialLink`], for tests and single-process deployments.
#[derive(Debug, Default)]
pub struct InMemoryCredentialLink {
    rows: Mutex<HashMap<(String, String), LinkedCredential>>,
}

impl InMemoryCredentialLink {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap in an `Arc` for handing to an authenticator.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    fn key(class: &CredentialClass, locator: &str) -> (String, String) {
        (class.as_str().to_string(), locator.to_string())
    }
}

#[async_trait]
impl CredentialLink for InMemoryCredentialLink {
    async fn link(&self, credential: LinkedCredential) -> Result<(), LinkError> {
        let key = Self::key(credential.class(), credential.locator());
        let mut rows = self.rows.lock().expect("credential link store poisoned");
        if let Some(existing) = rows.get(&key) {
            if existing.principal() != credential.principal() {
                return Err(LinkError::AlreadyLinked {
                    class: key.0,
                    locator: key.1,
                    existing: existing.principal().to_string(),
                });
            }
        }
        rows.insert(key, credential);
        Ok(())
    }

    async fn resolve(
        &self,
        class: CredentialClass,
        locator: &str,
    ) -> Result<Option<LinkedCredential>, LinkError> {
        let rows = self.rows.lock().expect("credential link store poisoned");
        Ok(rows.get(&Self::key(&class, locator)).cloned())
    }

    async fn credentials_for(
        &self,
        principal: &Principal,
    ) -> Result<Vec<LinkedCredential>, LinkError> {
        let rows = self.rows.lock().expect("credential link store poisoned");
        let mut out: Vec<LinkedCredential> = rows
            .values()
            .filter(|c| c.principal() == principal)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            (a.class(), a.locator()).cmp(&(b.class(), b.locator()))
        });
        Ok(out)
    }

    async fn unlink(&self, class: CredentialClass, locator: &str) -> Result<bool, LinkError> {
        let mut rows = self.rows.lock().expect("credential link store poisoned");
        Ok(rows.remove(&Self::key(&class, locator)).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const PUBKEY: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    fn alice() -> Principal {
        format!("idp:{UUID}").parse().unwrap()
    }

    #[tokio::test]
    async fn one_principal_many_credentials_resolve_to_one_subject() {
        let store = InMemoryCredentialLink::new();
        let alice = alice();

        // A password login and a nostr key: two credentials, one human.
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
                alice.clone(),
            ))
            .await
            .unwrap();

        let via_password = store
            .resolve(CredentialClass::Password, "alice")
            .await
            .unwrap()
            .unwrap();
        let via_nostr = store
            .resolve(CredentialClass::NostrKey, PUBKEY)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(via_password.principal(), via_nostr.principal());
        assert_eq!(via_password.principal(), &alice);

        let held = store.credentials_for(&alice).await.unwrap();
        assert_eq!(held.len(), 2);
    }

    #[tokio::test]
    async fn locators_are_scoped_by_class() {
        // The same string under two classes is two different credentials.
        let store = InMemoryCredentialLink::new();
        let alice = alice();
        let bob: Principal = "idp:00000000-0000-4000-8000-000000000001".parse().unwrap();

        store
            .link(LinkedCredential::new(
                CredentialClass::Password,
                "shared",
                alice.clone(),
            ))
            .await
            .unwrap();
        store
            .link(LinkedCredential::new(
                CredentialClass::ApiKey,
                "shared",
                bob.clone(),
            ))
            .await
            .unwrap();

        assert_eq!(
            store
                .resolve(CredentialClass::Password, "shared")
                .await
                .unwrap()
                .unwrap()
                .principal(),
            &alice
        );
        assert_eq!(
            store
                .resolve(CredentialClass::ApiKey, "shared")
                .await
                .unwrap()
                .unwrap()
                .principal(),
            &bob
        );
    }

    #[tokio::test]
    async fn a_credential_cannot_be_moved_to_another_principal() {
        let store = InMemoryCredentialLink::new();
        let alice = alice();
        let mallory: Principal = "idp:00000000-0000-4000-8000-00000000dead".parse().unwrap();

        store
            .link(LinkedCredential::new(
                CredentialClass::ApiKey,
                "k1",
                alice.clone(),
            ))
            .await
            .unwrap();

        // Re-linking to the same principal refreshes metadata.
        store
            .link(
                LinkedCredential::new(CredentialClass::ApiKey, "k1", alice.clone())
                    .with_roles(vec!["admin".into()]),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .resolve(CredentialClass::ApiKey, "k1")
                .await
                .unwrap()
                .unwrap()
                .roles(),
            ["admin"]
        );

        // Stealing it is refused.
        let err = store
            .link(LinkedCredential::new(
                CredentialClass::ApiKey,
                "k1",
                mallory,
            ))
            .await
            .unwrap_err();
        assert!(matches!(err, LinkError::AlreadyLinked { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn unlink_removes_only_the_named_credential() {
        let store = InMemoryCredentialLink::new();
        let alice = alice();
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
                CredentialClass::ApiKey,
                "k1",
                alice.clone(),
            ))
            .await
            .unwrap();

        assert!(store.unlink(CredentialClass::ApiKey, "k1").await.unwrap());
        assert!(!store.unlink(CredentialClass::ApiKey, "k1").await.unwrap());
        assert_eq!(store.credentials_for(&alice).await.unwrap().len(), 1);
    }

    #[test]
    fn credential_class_round_trips_including_unknown() {
        for c in [
            CredentialClass::Password,
            CredentialClass::ApiKey,
            CredentialClass::NostrKey,
            CredentialClass::Oidc,
            CredentialClass::Other("webauthn".into()),
        ] {
            assert_eq!(CredentialClass::from_stored(c.as_str()), c);
        }
    }

    #[test]
    fn expiry_is_opt_in() {
        let c = LinkedCredential::new(CredentialClass::ApiKey, "k", alice());
        assert!(!c.is_expired_at(Utc::now()));
        let c = c.expiring_at(Utc::now() - chrono::Duration::seconds(1));
        assert!(c.is_expired_at(Utc::now()));
    }
}
