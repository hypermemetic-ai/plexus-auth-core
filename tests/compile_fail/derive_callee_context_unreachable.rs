//! AUTHLANG-2 §"Acceptance criteria" 5 — a downstream crate cannot reach
//! `AuthContext::derive_callee_context`. The constructor is `pub(crate)`
//! to `plexus-auth-core`, so any attempt to call it from outside the
//! crate must fail to compile.
//!
//! This is the structural defense of AUTHZ-0 §"The sealed-type pattern":
//! a `ForwardPolicy` impl returns a `ForwardDerivation` (parameters) and
//! the framework — the only entity with crate-internal access — mints the
//! callee context. Policies can shrink; they cannot grow; they cannot
//! construct sealed values.
//!
//! Test strategy: receive a `&Principal` as a parameter (downstream crates
//! routinely receive sealed values from the framework as borrows) and
//! attempt to call `derive_callee_context` with it. The compiler must
//! reject the call because `derive_callee_context` is `pub(crate)`.

use plexus_auth_core::{AuthContext, ForwardDerivation, Principal};

fn try_derive(caller: &AuthContext, stamp: &Principal) -> AuthContext {
    let derivation = ForwardDerivation::IDENTITY_ONLY;
    AuthContext::derive_callee_context(caller, &derivation, stamp)
}

fn main() {
    let _ = try_derive;
}
