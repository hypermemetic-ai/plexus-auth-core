//! AUTHZ-DATA-1-WRAPPER §"`Scoped<'a, S>` borrow", row "Internal handles"
//! — `Scoped`'s inner store reference is module-private. Activation code
//! that reaches `scoped.inner` directly fails to compile; the only
//! accessor is `scoped.store()` (and `scoped.tenant()`).

use plexus_auth_core::tenant::storage::reference::InMemoryKvStore;
use plexus_auth_core::Scoped;

fn leak(s: &Scoped<'_, InMemoryKvStore>) {
    let _inner = s.inner;
}

fn main() {}
