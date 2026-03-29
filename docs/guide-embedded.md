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

### 1. Configure the policy

```rust
use zerolease::lease::LeaseTerms;
use zerolease::policy::{AgentPattern, PolicyConfig, PolicyEngine, PolicyGrant, SecretPattern};
use zerolease::types::{AgentId, DomainScope, SecretName};

let policy = PolicyEngine::new(PolicyConfig {
    default_lease_terms: LeaseTerms::default_short(), // 15 min, non-renewable
    grants: vec![
        PolicyGrant {
            agent: AgentPattern::Exact(AgentId::new("tool-git")),
            secret: SecretPattern::Exact(SecretName::new("github-pat")),
            allowed_domains: vec![DomainScope::new("github.com")],
            lease_terms: Some(LeaseTerms {
                ttl: chrono::TimeDelta::minutes(15),
                renewable: false,
                max_uses: Some(10),
            }),
        },
    ],
});
```

Policy can also be loaded from a JSON file (see [cloud service guide](guide-cloud-service.md)):

```rust
let policy = PolicyEngine::new(PolicyConfig::from_file("policy.json")?);
```

### 2. Initialize the vault at startup

```rust
use zerolease::keysource::keychain::KeychainSource;
use zerolease::store::CipherAlgorithm;
use zerolease::vault::Vault;
use zerolease_store_rusqlite::{RusqliteStore, RusqliteAuditLog};

// Load the DEK from the OS keychain.
let key_source = KeychainSource::new("myapp", "vault-dek").await?;

// Open (or create) the SQLite databases.
let store = RusqliteStore::new("secrets.db").await?;
let audit = RusqliteAuditLog::new("audit.db").await?;

// Create and initialize the vault.
let vault = Vault::new(key_source, store, audit, policy, CipherAlgorithm::Aes256Gcm);
vault.initialize().await?;
```

### 3. Store credentials (admin operation)

```rust
use zerolease::store::SecretKind;
use zerolease::transport::PeerIdentity;

vault.store_secret(
    &SecretName::new("github-pat"),
    b"ghp_abc123...",
    SecretKind::Pat,
    Some("GitHub PAT for repo access".into()),
    &PeerIdentity::Anonymous,  // admin, no transport peer
).await?;
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
    "github.com",  // target domain as &str
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

[zeroclaw](https://github.com/ceejbot/zeroclaw) is the primary consumer of the embedded model. The integration is described in detail in the
[Credential Sidecar — Embedded Deployment](design-credential-sidecar-embedded.md) design doc.

The high-level approach:

1. **Feature gate `embedded-vault`** in zeroclaw's `Cargo.toml` pulls in
   the full zerolease crate with vault, SQLite store, and keychain support.
2. **In-process vault** constructed at startup:
   `Vault<KeychainSource, RusqliteStore, RusqliteAuditLog>`.
3. **Session-scoped access**: each incoming user message creates a session;
   credentials are leased within that session's scope and revoked when the
   session ends.
4. **Process supervisor** wraps CLI tools and MCP servers — credentials are
   delivered via anonymous pipe (fd-based), not environment variables. A
   thin credential shim reads the fd, sets the env var, and `exec`s the tool.
5. **Tool-to-secret bindings** in the policy ensure each tool can only access
   the credentials it needs.
6. **Fail-closed**: if vault initialization fails, zeroclaw refuses to start
   rather than falling back to plaintext credentials.

zeroclaw's existing `CredentialProvider` trait and `build_credential_provider()`
function are the integration points — tools are unaware of the vault. See
the design doc for implementation phases and security considerations.
