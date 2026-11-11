# plexus-auth-core

Who is calling a Plexus RPC service, and what they may call: `AuthContext`,
`Principal`, credentials, tenants, roles and grants, and the gate that
answers each call.

## Most people want plexus-rpc

A service takes one dependency, [plexus-rpc](https://github.com/hypermemetic-ai/plexus-rpc),
which brings this crate as `plexus_rpc::auth_core`. Its README shows a
service with users.

## Install

```toml
[dependencies]
plexus-auth-core = "0.3"
```

| feature | what it turns on |
| -- | -- |
| `adapters` | The ways a caller proves who it is: OIDC, nostr, agent keys |
| `oidc-reqwest` | An HTTP fetcher for the OIDC validator's discovery and keys |
| `test-support` | Constructors for a crate's own tests, for `[dev-dependencies]` only |

## A caller

```rust
use plexus_auth_core::identity::Principal;
use plexus_auth_core::AuthContext;

let principal: Principal = "key:2fe0a8167e552fd7c0b2713c953b9993a5b187d67a11695adcb266e94ec83006".parse().unwrap();
let caller = AuthContext::for_principal(&principal, "session-1", vec!["viewer".to_string()], serde_json::Value::Null);

assert!(caller.is_authenticated());
assert!(caller.has_role("viewer"));
assert_eq!(caller.principal(), Some(principal));

let nobody = AuthContext::anonymous();
assert!(!nobody.is_authenticated());
assert!(nobody.principal().is_none());
```

`cargo test --doc` runs this block.

## Reference

- [docs.rs/plexus-auth-core](https://docs.rs/plexus-auth-core)
- [CHANGELOG.md](CHANGELOG.md)
