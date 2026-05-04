//! AUTHZ-CORE-CRATE-1 §"Required behavior" — Principal::Anonymous LOOKS
//! like a fieldless variant a caller could construct directly. The seal
//! holds because `Principal::anonymous_sealed` is the only path, and it's
//! `pub(crate)`. Note: `Principal::Anonymous` IS a public variant of a
//! pub enum, so `Principal::Anonymous` itself compiles. This compile-fail
//! asserts that the SEALED constructor `anonymous_sealed` is unreachable.
//!
//! (A future tightening will make all variants payload-gated. Documented
//! in RUN-NOTES.)

use plexus_auth_core::Principal;

fn main() {
    let _ = Principal::anonymous_sealed();
}
