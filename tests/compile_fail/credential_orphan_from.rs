//! AUTHZ-CRED-CORE-1 acceptance criterion 8: no third crate may add an
//! `impl From<X> for Credential<T>` where both `X` and `Credential<T>` are
//! foreign. Rust's orphan rule rejects it — `From` is a foreign trait and
//! `Credential<T>` is a foreign type, and a foreign source type means no
//! parameter is local.
//!
//! Both the trait (`From`) and the implementing type (`Credential<String>`)
//! are foreign to this crate, and the source type (`String`) is also
//! foreign (defined in `alloc`). Rust's coherence rules reject the impl.

use plexus_auth_core::Credential;

// Foreign trait `From`, foreign type `Credential<String>`, foreign source
// `String` (from `alloc`). No type parameter is local. Orphan-rule
// rejection:
//
//   error[E0117]: only traits defined in the current crate can be implemented
//                 for types defined outside of the crate.
impl From<String> for Credential<String> {
    fn from(_: String) -> Self {
        unreachable!("never reached; this impl does not compile")
    }
}

fn main() {}
