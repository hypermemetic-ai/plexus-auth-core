//! AUTHZ-DATA-1-TYPES §"What must NOT change" / AUTHZ-0 §"The sealed-
//! type pattern" — `Tenant` does not derive `Default`. A default tenant
//! value would silently widen the isolation boundary (all callers
//! without an explicit tenant resolving to the same one). This trybuild
//! program asserts no `Default` impl exists.

use plexus_auth_core::Tenant;

fn requires_default<T: Default>() {}

fn main() {
    requires_default::<Tenant>();
}
