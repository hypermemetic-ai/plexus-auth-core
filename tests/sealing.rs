//! Acceptance tests for the sealed-type guarantees that AUTHZ-CORE-CRATE-1
//! demands. Each `tests/compile_fail/*.rs` file is a small program that
//! attempts to construct a sealed value from outside `plexus-auth-core`.
//! `trybuild` runs the compiler against each one and asserts it FAILS to
//! compile — that compile failure is the structural defense.
//!
//! Per the ticket §"Acceptance criteria":
//!
//!   6. A new test in `plexus-auth-core/tests/` asserts that `AuthContext`
//!      cannot be constructed from outside the crate (intentionally
//!      compile-fails using `trybuild` or equivalent).
//!
//!   7. A new test asserts no `Default` impl exists on `AuthContext`
//!      (compile-fail or `static_assertions`).
//!
//! The compile-fail programs cover:
//!
//!   - VerifiedUser cannot be constructed externally (private constructor +
//!     private fields)
//!   - Principal cannot be constructed externally (all variants gated)
//!   - ServiceIdentity cannot be constructed externally
//!   - VerifiedUser does not implement Default
//!   - Principal does not implement Default
//!   - Tenant cannot be constructed externally (AUTHZ-DATA-1-TYPES §5)
//!   - Tenant has no public field (struct-literal fabrication rejected)
//!   - Tenant does not implement Default (no silent isolation widening)
//!
//! AuthContext currently retains its `pub` constructor and `pub` fields
//! (see RUN-NOTES). The full external-construction lockdown for
//! AuthContext lands in a follow-up ticket once call sites are migrated.
//! In the meantime, the protections that DO hold today for AuthContext
//! are also asserted: no Default impl, and the orphan-rule guarantee
//! (which is a property of Rust's coherence rules, not of an attribute on
//! the type — captured here by inspection in the architecture doc).
//!
//! AUTHZ-CRED-CORE-1 adds compile-fail asserts for the credential
//! primitive (acceptance criteria 6, 7, 8 plus §"Forbidden constructions"
//! and the Tier B Q-WIRE-3 dispatch-capture guard):
//!
//!   - `Credential::new_sealed` is unreachable externally
//!   - `Credential { .. }` struct-literal construction is unreachable
//!   - `Credential<T>` does not implement `Default`
//!   - `CredentialMinter::new_sealed` is unreachable externally
//!   - `impl From<X> for Credential<T>` from a third crate is rejected by
//!     Rust's orphan rule (acceptance criterion 8)
//!   - `Credential<T>` is not `Deserialize` (raw JSON cannot fabricate one)
//!   - `DispatchCaptureGuard::install` is unreachable externally (so the
//!     dispatch-side capture toggle cannot be activated by activation code)

#[test]
fn sealing_compile_fails() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/verified_user_construct.rs");
    t.compile_fail("tests/compile_fail/verified_user_field_access.rs");
    t.compile_fail("tests/compile_fail/principal_user_construct.rs");
    t.compile_fail("tests/compile_fail/principal_anonymous_construct.rs");
    t.compile_fail("tests/compile_fail/service_identity_construct.rs");
    t.compile_fail("tests/compile_fail/verified_user_no_default.rs");
    t.compile_fail("tests/compile_fail/principal_no_default.rs");
    t.compile_fail("tests/compile_fail/auth_context_no_default.rs");
    t.compile_fail("tests/compile_fail/tenant_construct.rs");
    t.compile_fail("tests/compile_fail/tenant_field_access.rs");
    t.compile_fail("tests/compile_fail/tenant_no_default.rs");

    // AUTHZ-CRED-CORE-1 acceptance criteria 6, 7, 8 (and the broader
    // sealed-construction asserts called out in §"Forbidden constructions"
    // and Tier B Q-WIRE-3).
    t.compile_fail("tests/compile_fail/credential_construct.rs");
    t.compile_fail("tests/compile_fail/credential_struct_literal.rs");
    t.compile_fail("tests/compile_fail/credential_no_default.rs");
    t.compile_fail("tests/compile_fail/credential_minter_construct.rs");
    t.compile_fail("tests/compile_fail/credential_orphan_from.rs");
    t.compile_fail("tests/compile_fail/credential_no_deserialize.rs");
    t.compile_fail("tests/compile_fail/dispatch_capture_guard_construct.rs");
}
