//! AUTHZ-DATA-1-WRAPPER §"Acceptance criteria" item 2 — a sibling crate
//! cannot construct a `Tenanted<S>` directly. `Tenanted::new_sealed` is
//! `pub(crate)` to `plexus-auth-core`; activation code receives a
//! `Tenanted<S>` from the framework's hub-builder layer and cannot mint
//! one itself.

use plexus_auth_core::tenant::storage::reference::InMemoryKvStore;
use plexus_auth_core::Tenanted;

fn main() {
    let store = InMemoryKvStore::new();
    let _ = Tenanted::new_sealed(store);
}
