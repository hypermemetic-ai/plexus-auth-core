//! AUTHZ-DATA-1-WRAPPER §"Failing examples" row 1 — an activation that
//! reaches for the inner store directly (`self.store.inner.method()`)
//! fails to compile because `Tenanted::inner` is module-private to
//! `plexus-auth-core::tenant::storage`.
//!
//! Diagnostic: `field 'inner' of struct 'Tenanted' is private` (E0616).

use plexus_auth_core::tenant::storage::reference::InMemoryKvStore;
use plexus_auth_core::Tenanted;

fn leak(t: &Tenanted<InMemoryKvStore>) {
    let _inner = &t.inner;
}

fn main() {}
