# Guide: Embedded in an Application (zeroclaw)

This guide describes how to integrate zerolease directly into a Rust application that manages AI agents — the way [zeroclaw](https://github.com/ceejbot/zeroclaw) uses it.

## When to Use This

You're building an application that orchestrates AI agents and their tools. The application already manages tool execution and wants fine-grained control over which tools get which credentials, for how long, and for which domains. You want the vault in-process, not as a separate service.

## Architecture

```
Your Application
├── Vault<KeychainSource, RusqliteStore, RusqliteAuditLog>
├── PolicyEngine (configured with grant rules)
├── Tool A: request_lease → access_secret → do work → drop guard
├── Tool B: request_lease → access_secret → do work → drop guard
└── Audit log (queryable: "what did Tool A access?")
```

The vault runs in-process. No server, no transport, no proxy. Tools call the vault API directly through Rust function calls.

## Choosing Backends

For an embedded application on a single machine:

| Backend | Crate | Why |
|---------|-------|-----|
| **KeySource** | `KeychainSource` | OS keychain (macOS Keychain, Linux secret-service). DEK never touches disk. |
| **SecretStore** | `zerolease-store-rusqlite` | Single SQLite file. Zero config. Same process. |
| **AuditLog** | `RusqliteAuditLog` | Queryable audit in the same SQLite DB (or a separate one). |

Add to your `Cargo.toml`:

```toml
[dependencies]
zerolease = { version = "0.1" }
zerolease-store-rusqlite = { version = "0.1" }
```

## Integration Pattern

### 1. Initialize the vault at startup

```rust
use zerolease::keysource::keychain::KeychainSource;
use zerolease::policy::PolicyEngine;
use zerolease::vault::Vault;
use zerolease_store_rusqlite::{RusqliteStore, RusqliteAuditLog};

// Load the DEK from the OS keychain.
let key_source = KeychainSource::new("myapp", "vault-dek").await?;

// Open (or create) the SQLite databases.
let store = RusqliteStore::new("secrets.db").await?;
let audit = RusqliteAuditLog::new("audit.db").await?;

// Configure the policy engine.
let policy = PolicyEngine::new(grants);

// Create the vault.
let vault = Vault::new(key_source, store, audit, policy);
```

### 2. Store credentials (admin operation)

```rust
use zerolease::store::SecretKind;
use zerolease::transport::PeerIdentity;
use zerolease::types::SecretName;

vault.store_secret(
    &SecretName::new("github-pat"),
    b"ghp_abc123...",
    SecretKind::Pat,
    Some("GitHub PAT for repo access".into()),
    &PeerIdentity::Anonymous,  // admin, no transport peer
).await?;
```

### 3. Grant access via policy

```rust
use zerolease::policy::{PolicyGrant, GrantScope};
use zerolease::types::{AgentId, DomainScope, SecretName};

let grants = vec![
    PolicyGrant {
        agent: AgentId::new("tool-git"),
        secret: SecretName::new("github-pat"),
        domains: vec![DomainScope::new("github.com")],
        max_ttl_seconds: 900,      // 15 minutes
        max_uses: Some(10),
        renewable: false,
    },
];
```

### 4. Lease credentials per-tool

```rust
let peer = PeerIdentity::Anonymous; // in-process, no transport

// Tool requests a lease.
let grant = vault.request_lease(
    &AgentId::new("tool-git"),
    &SecretName::new("github-pat"),
    &DomainScope::new("github.com"),
    &peer,
).await?;

// Tool accesses the secret through the lease.
let guard = vault.access_secret(
    &grant.lease_id,
    &DomainScope::new("github.com"),
    &peer,
).await?;

// Use the credential. It's zeroized when `guard` drops.
guard.expose(|token| {
    // Use token for git operation.
});
// guard dropped here → secret zeroized from memory
```

### 5. Query the audit log

```rust
let events = audit.query_by_agent(
    &AgentId::new("tool-git"),
    100
).await?;

for event in events {
    println!("{}: {:?}", event.timestamp, event.event);
}
```

## Adapting zeroclaw

[zeroclaw](https://github.com/ceejbot/zeroclaw) has a built-in credential store. To replace it with zerolease:

1. **Add the zerolease dependencies** to zeroclaw's `Cargo.toml`.
2. **Replace the built-in vault** with `Vault<KeychainSource, RusqliteStore, RusqliteAuditLog>`. zeroclaw already uses rusqlite, so the `zerolease-store-rusqlite` crate avoids `libsqlite3-sys` link conflicts (it uses rusqlite, not sqlx).
3. **Adapt tool credential injection.** Where zeroclaw currently hands tools a raw credential string, replace with the lease-and-access pattern above. Each tool gets a `LeaseGuard` scoped to the domain it needs.
4. **Configure the policy engine** from zeroclaw's existing permission model. The flat grant list maps naturally to zeroclaw's per-tool permission declarations.
5. **Wire the audit log** to zeroclaw's observability. The `RusqliteAuditLog` is queryable; the `TracingAuditLog` emits structured events to the tracing subscriber.

The key change is moving from "tool holds a credential for its lifetime" to "tool leases a credential for each operation." The vault's domain scoping and TTLs prevent lateral movement even if a tool is compromised.
