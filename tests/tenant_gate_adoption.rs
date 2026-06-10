//! Non-trak adoption demo for the generalized `TenantGate` (UT-1 AC 1).
//!
//! A minimal "notes backend" — deliberately nothing like trak's
//! FacetStore — adopts the gate and demonstrates the contract:
//!
//! - cross-tenant reads return **not-found** (indistinguishable from a
//!   genuinely missing note: no existence oracle);
//! - cross-tenant writes return **forbidden**;
//! - anonymous writes return **unauthenticated**;
//! - create stamps the caller's *resolved* tenant, overwriting forged
//!   values (tenant-hop defense);
//! - listing filters foreign-tenant rows.
//!
//! This is the integration-level demo; a live backend adoption (e.g. a
//! fidget-spinner activation) is the remaining slice of AC 1 and rides
//! with the UT-V gauntlet.

use std::collections::HashMap;
use std::sync::Mutex;

use plexus_auth_core::{
    AuthContext, ClaimTenantResolver, GateDenial, TenantGate, TenantId, TenantTagged,
};
use serde_json::json;
use uuid::Uuid;

// ─── The toy backend's domain ───────────────────────────────────────────

#[derive(Debug, Clone)]
struct Note {
    id: Uuid,
    text: String,
    /// Where THIS backend chooses to store its tenant tag — a plain
    /// column, unlike trak's `meta.extra["tenant"]` placement. The gate
    /// doesn't care; `TenantTagged` is the seam.
    tenant: Option<TenantId>,
}

impl TenantTagged for Note {
    fn tenant_tag(&self) -> Option<TenantId> {
        self.tenant.clone()
    }
}

#[derive(Debug)]
enum NoteError {
    NotFound,
    Forbidden,
    Unauthenticated,
}

impl From<GateDenial> for NoteError {
    fn from(d: GateDenial) -> Self {
        match d {
            GateDenial::NotFound => Self::NotFound,
            GateDenial::Forbidden => Self::Forbidden,
            GateDenial::Unauthenticated => Self::Unauthenticated,
        }
    }
}

/// The backend: an in-memory store + per-request gate construction —
/// the same shape the trak adapter takes (see `tenant::gate` rustdoc).
#[derive(Default)]
struct NotesBackend {
    rows: Mutex<HashMap<Uuid, Note>>,
}

impl NotesBackend {
    async fn gate(&self, auth: Option<&AuthContext>) -> TenantGate {
        // org_id default + tenant_id alias; claim required (no
        // single-user fallback) to make cross-tenant outcomes explicit.
        let resolver = ClaimTenantResolver {
            claim_key: "org_id".into(),
            single_user_fallback: false,
        };
        TenantGate::from_auth(&resolver, auth).await
    }

    async fn create(
        &self,
        auth: Option<&AuthContext>,
        text: &str,
        forged_tenant: Option<TenantId>,
    ) -> Result<Note, NoteError> {
        let gate = self.gate(auth).await;
        // The caller's resolved tenant wins; any forged tag is discarded.
        let stamp = gate.stamp()?;
        let _ = forged_tenant; // what a malicious caller *tried* to set
        let note = Note {
            id: Uuid::new_v4(),
            text: text.to_string(),
            tenant: Some(stamp),
        };
        self.rows.lock().unwrap().insert(note.id, note.clone());
        Ok(note)
    }

    async fn get(&self, auth: Option<&AuthContext>, id: Uuid) -> Result<Note, NoteError> {
        let gate = self.gate(auth).await;
        let note = self
            .rows
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or(NoteError::NotFound)?;
        gate.authorize_read_of(&note)?;
        Ok(note)
    }

    async fn update_text(
        &self,
        auth: Option<&AuthContext>,
        id: Uuid,
        text: &str,
    ) -> Result<(), NoteError> {
        let gate = self.gate(auth).await;
        let mut rows = self.rows.lock().unwrap();
        let note = rows.get_mut(&id).ok_or(NoteError::NotFound)?;
        gate.authorize_write_of(note)?;
        note.text = text.to_string();
        Ok(())
    }

    async fn list(&self, auth: Option<&AuthContext>) -> Vec<Note> {
        let gate = self.gate(auth).await;
        self.rows
            .lock()
            .unwrap()
            .values()
            .filter(|n| gate.visible(*n))
            .cloned()
            .collect()
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn caller(user: &str, org: &str) -> AuthContext {
    AuthContext::new(
        user.to_string(),
        "sess-1".to_string(),
        vec![],
        json!({"org_id": org}),
    )
}

// ─── The demo ───────────────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_read_returns_not_found() {
    let backend = NotesBackend::default();
    let acme = caller("alice", "org_acme");
    let neon = caller("nika", "org_neon");

    let note = backend
        .create(Some(&acme), "acme quarterly numbers", None)
        .await
        .unwrap();

    // Owner reads fine.
    assert_eq!(
        backend.get(Some(&acme), note.id).await.unwrap().text,
        "acme quarterly numbers"
    );

    // Foreign tenant gets NOT-FOUND — the same error a random UUID gets,
    // so existence cannot be probed.
    let foreign = backend.get(Some(&neon), note.id).await.unwrap_err();
    assert!(matches!(foreign, NoteError::NotFound));
    let missing = backend.get(Some(&neon), Uuid::new_v4()).await.unwrap_err();
    assert!(matches!(missing, NoteError::NotFound));
}

#[tokio::test]
async fn cross_tenant_write_returns_forbidden() {
    let backend = NotesBackend::default();
    let acme = caller("alice", "org_acme");
    let neon = caller("nika", "org_neon");

    let note = backend.create(Some(&acme), "v1", None).await.unwrap();
    let err = backend
        .update_text(Some(&neon), note.id, "defaced")
        .await
        .unwrap_err();
    assert!(matches!(err, NoteError::Forbidden));

    // The note is untouched.
    assert_eq!(backend.get(Some(&acme), note.id).await.unwrap().text, "v1");
}

#[tokio::test]
async fn anonymous_writes_are_unauthenticated() {
    let backend = NotesBackend::default();
    let err = backend.create(None, "drive-by", None).await.unwrap_err();
    assert!(matches!(err, NoteError::Unauthenticated));
}

#[tokio::test]
async fn create_stamp_defeats_tenant_hop() {
    let backend = NotesBackend::default();
    let acme = caller("alice", "org_acme");

    // The caller tries to plant the note in org_neon. The gate's stamp
    // (resolved tenant) wins.
    let forged = TenantId::try_new("org_neon").unwrap();
    let note = backend
        .create(Some(&acme), "hop attempt", Some(forged))
        .await
        .unwrap();
    assert_eq!(note.tenant.as_ref().map(|t| t.as_str()), Some("org_acme"));

    // And org_neon cannot see it.
    let neon = caller("nika", "org_neon");
    assert!(matches!(
        backend.get(Some(&neon), note.id).await.unwrap_err(),
        NoteError::NotFound
    ));
}

#[tokio::test]
async fn listing_filters_foreign_tenants() {
    let backend = NotesBackend::default();
    let acme = caller("alice", "org_acme");
    let neon = caller("nika", "org_neon");

    backend.create(Some(&acme), "a1", None).await.unwrap();
    backend.create(Some(&acme), "a2", None).await.unwrap();
    backend.create(Some(&neon), "n1", None).await.unwrap();

    let acme_view = backend.list(Some(&acme)).await;
    assert_eq!(acme_view.len(), 2);
    assert!(acme_view.iter().all(|n| n.text.starts_with('a')));

    let neon_view = backend.list(Some(&neon)).await;
    assert_eq!(neon_view.len(), 1);
    assert_eq!(neon_view[0].text, "n1");

    // Anonymous sees nothing (every note is tenant-owned).
    assert!(backend.list(None).await.is_empty());
}

#[tokio::test]
async fn forged_auth_context_is_treated_as_anonymous() {
    let backend = NotesBackend::default();
    // Tenancy claim present but no valid session: the gate's
    // defense-in-depth check resolves this caller to anonymous.
    let forged = AuthContext::new(
        "mallory".into(),
        String::new(),
        vec![],
        json!({"org_id": "org_acme"}),
    );
    let err = backend.create(Some(&forged), "x", None).await.unwrap_err();
    assert!(matches!(err, NoteError::Unauthenticated));
}
