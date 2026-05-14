//! AUTHZ-CRED-CORE-1 acceptance criterion 7: `Credential<T>` does not
//! implement `Default`. A default credential would be an unsigned,
//! anonymously-minted value with no metadata — a security footgun.

use plexus_auth_core::Credential;

fn main() {
    let _: Credential<String> = Default::default();
}
