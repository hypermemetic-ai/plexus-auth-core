//! AUTHZ-CRED-CORE-1 §"Required behavior" / Tier B Q-WIRE-3 — the
//! dispatch-capture toggle's setter is unreachable from any non-framework
//! crate. The `DispatchCaptureGuard::install` constructor is `pub(crate)`;
//! external code cannot install a guard, so it cannot capture inner values
//! into the sidecar by emitting `Serialize` on a credential.

fn main() {
    // The guard type is `pub` so it can appear in framework signatures,
    // but its constructor is crate-private. This fails to compile.
    let _ = plexus_auth_core::credential::DispatchCaptureGuard::install();
}
