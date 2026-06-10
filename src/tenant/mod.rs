//! Tenant primitives — AUTHZ-0 layer 4 (data isolation).
//!
//! This module hosts the sealed `Tenant` value, the `TenantError` enum,
//! and the `TenantResolver` trait + default implementations. Together they
//! are the structural foundation for tenant isolation:
//!
//! - `Tenant` is a sealed newtype over `String`. The constructor is
//!   `pub(crate)` to `plexus-auth-core`. Activation code cannot fabricate a
//!   `Tenant` from a string literal: the only path to a `Tenant` value is
//!   through the framework's `TenantResolver`, which derives one from a
//!   verified `AuthContext`.
//!
//! - `TenantResolver` is an async trait. Backends supply an impl;
//!   `ClaimTenantResolver` covers the 80% case (pull tenant from a JWT
//!   claim) and `SingleTenantResolver` is the explicit opt-out for
//!   single-user dev installs.
//!
//! - The seal escalates from procedural (visibility within one crate) to
//!   structural (crate-private constructor that no other crate can reach),
//!   per AUTHZ-0 §"Crate-level isolation amplifies the seal".
//!
//! UT-1 adds two pieces on top:
//!
//! - `TenantId` (in [`types`]) — the public, validated identifier newtype
//!   for tenant identity (claim values, stored tags). Data, not proof —
//!   see its docs for the `TenantId` vs `Tenant` distinction.
//!
//! - `TenantGate` (in [`gate`]) — the generalized tenant-isolation
//!   predicate layer extracted from plexus-trak's reference gate: reads
//!   scoped not-found, writes forbidden, anonymous writes
//!   unauthenticated. Any backend registers it per request.
//!
//! See `plans/AUTHZ/AUTHZ-DATA-1-TYPES.md` for the ticket contract,
//! `plans/AUTHZ/AUTHZ-DATA-S01-output.md` §§1-2 for the design, and the
//! UT-S01 decision doc (trak facet `884cd6ad`) for the UT-1 scope.

pub mod gate;
pub mod resolver;
pub mod storage;
pub mod types;

pub use gate::{GateDenial, TenantGate, TenantTagged};
pub use resolver::{ClaimTenantResolver, SingleTenantResolver, TenantResolver};
pub use storage::{Scoped, TenantBoundary, TenantScopedStore, Tenanted};
pub use types::{Tenant, TenantError, TenantId};
