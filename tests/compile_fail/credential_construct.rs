//! AUTHZ-CRED-CORE-1 acceptance criterion 6: `Credential::new(...)` is
//! unreachable from outside `plexus-auth-core`.
//!
//! The credential's only constructor (`new_sealed`) is `pub(crate)` and the
//! fields are private; together this makes construction from any other
//! crate impossible. This program tries the obvious paths and must fail.

use plexus_auth_core::Credential;

fn main() {
    // Attempt 1: the (sealed) constructor.
    let _: Credential<String> = Credential::new_sealed(
        "fabricated".to_string(),
        unreachable!("can't even build metadata externally without the sealed deps"),
        unreachable!(),
    );
}
