//! AUTHZ-CRED-CORE-1 §"Required behavior" / Tier B Q-WIRE-3 / AUTHZ-CRED-CORE-1B:
//! the raw `DispatchCaptureGuard::install` constructor is unreachable from
//! any non-framework crate. External code must go through the public
//! scoped-callback API (`run_with_credential_capture`), which bounds the
//! guard's lifetime to the closure invocation.
//!
//! The seal property is "the guard's lifetime is bounded by the function
//! call" — external code can trigger a capture, but cannot retain a guard.
//! Asserting `install` is still `pub(crate)` after CRED-CORE-1B preserves
//! that property.

fn main() {
    // The guard type is `pub` so it can appear in framework signatures,
    // but its constructor is crate-private. This fails to compile.
    let _ = plexus_auth_core::credential::DispatchCaptureGuard::install();

    // The public, scoped entry point IS reachable — but a successful
    // compile here would mask the failure above. The `compile_fail`
    // testharness only requires AT LEAST ONE compile error in the file.
    // We leave the call here as documentation that the entry point exists
    // and is reachable; cargo test in `src/credential.rs` exercises it
    // and confirms the runtime behavior.
    let _: (u32, Vec<plexus_auth_core::credential::CapturedCredential>) =
        plexus_auth_core::credential::run_with_credential_capture(|| 0_u32);
}
