//! AUTHZ-CRED-CORE-1 §"Required behavior" — the `CredentialMinter`'s
//! constructor is `pub(crate)`. Activation code receives a reference; no
//! external path produces one.

use plexus_auth_core::{CredentialIssuer, CredentialMinter, MethodPath, Origin};

fn main() {
    // The minter's constructor is crate-private; this fails to compile.
    let issuer = CredentialIssuer::new(
        Origin::new("ws://example"),
        MethodPath::try_new("auth.login").unwrap(),
    );
    let _ = CredentialMinter::new_sealed(issuer);
}
