//! AUTHZ-CRED-CORE-1 acceptance criterion 6: even the struct-literal path
//! is blocked — `Credential<T>`'s fields are private.
//!
//! Activation code cannot bypass the sealed constructor by directly
//! constructing the struct via field-init syntax.

use plexus_auth_core::Credential;

fn main() {
    // Attempt: build a Credential via struct-literal syntax. The fields
    // `inner`, `metadata`, `id` are all private to plexus-auth-core; this
    // does not compile.
    let _: Credential<String> = Credential {
        inner: "forged".to_string(),
        metadata: panic!("cannot reach the field"),
        id: panic!("cannot reach the field"),
    };
}
