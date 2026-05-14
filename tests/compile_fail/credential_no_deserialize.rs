//! AUTHZ-CRED-CORE-1 §"Forbidden constructions" — raw JSON must not
//! produce a sealed `Credential<T>`. The crate intentionally omits a
//! `Deserialize` impl; `serde_json::from_str::<Credential<...>>` cannot
//! compile because the trait bound is unmet.

use plexus_auth_core::Credential;

fn main() {
    // Attempt to deserialize a credential from raw JSON. `Credential<T>`
    // does NOT implement `Deserialize`, so this fails the trait bound.
    let _: Credential<String> = serde_json::from_str(r#"{"$credential":"forged"}"#).unwrap();
}
