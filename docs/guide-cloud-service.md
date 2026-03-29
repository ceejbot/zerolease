# Guide: Cloud Service Deployment

This guide describes deploying zerolease as a server process that manages credentials for a shared infrastructure — multiple services, CI/CD pipelines, or orchestrators accessing a central credential store.

## When to Use This

You have a persistent infrastructure (not disposable VMs) where multiple processes need credential access. You want centralized policy, audit logging, and the ability to rotate credentials without redeploying consumers. The vault runs as a server process; clients connect over Unix domain sockets or TCP.

## Architecture

```
┌─────────────────────────────────────────┐
│  Host / Server                          │
│                                         │
│  zerolease vault server                 │
│  ├── KeySource: KmsSource (AWS KMS)     │
│  ├── SecretStore: PostgresStore         │
│  ├── AuditLog: TracingAuditLog → ELK   │
│  └── Authenticator: (your impl)        │
│       │                                 │
│       ├── UDS  → local orchestrator     │
│       └── TCP  → CI runners, services   │
│                                         │
│  Service A ──UDS──→ vault               │
│  Service B ──UDS──→ vault               │
│  CI runner ──TCP──→ vault               │
└─────────────────────────────────────────┘
```

## Choosing Backends

| Backend | Crate | Why |
|---------|-------|-----|
| **KeySource** | `KmsSource` (feature `kms`) | DEK encrypted by AWS KMS. No key material on disk. |
| **SecretStore** | `zerolease-store-postgres` | Shared PostgreSQL. Backups, replication, familiar ops. |
| **AuditLog** | `TracingAuditLog` (core crate) | Structured events → stdout → fluentd/vector → your log aggregator. |

For smaller deployments, `RusqliteStore + RusqliteAuditLog` on a single host works fine.

For AWS-native deployments where you want AWS to manage the encrypted blobs: `AwsSecretsManagerStore + TracingAuditLog`.

## Running the Vault Server

The vault server is not yet a standalone binary (it's a library). You write a small Rust program that configures the backends and starts the server:

```rust
use std::sync::Arc;
use zerolease::keysource::kms::KmsSource;
use zerolease::policy::PolicyEngine;
use zerolease::audit::tracing_log::TracingAuditLog;
use zerolease::server::VaultServer;
use zerolease::transport::uds::UdsListener;
use zerolease_store_postgres::PostgresStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let key_source = KmsSource::new(
        "alias/zerolease-prod",
        "us-west-2",
        "/var/lib/zerolease/dek.enc",
    ).await?;

    let store = PostgresStore::new(
        "postgres://zerolease:password@db.internal/zerolease"
    ).await?;

    let audit = TracingAuditLog::new();
    let policy = PolicyEngine::new(PolicyConfig::from_file("policy.json")?);
    let vault = Vault::new(key_source, store, audit, policy, CipherAlgorithm::Aes256Gcm);
    vault.initialize().await?;
    let vault = Arc::new(vault);

    let listener = UdsListener::bind("/var/run/zerolease/vault.sock")?;
    let authenticator = Arc::new(your_authenticator());

    let server = VaultServer::new(vault, listener, authenticator);
    server.serve().await?;

    Ok(())
}
```

## Authentication

You implement the `Authenticator` trait to map peer identity to roles:

```rust
use zerolease::auth::{Authenticator, ConnectionIdentity, Role};
use zerolease::transport::PeerIdentity;
use zerolease::types::AgentId;

struct MyAuthenticator { /* ... */ }

#[async_trait::async_trait]
impl Authenticator for MyAuthenticator {
    async fn authenticate(
        &self,
        peer: &PeerIdentity,
        token: Option<&str>,
    ) -> Option<ConnectionIdentity> {
        match peer {
            // Local orchestrator process (known UID).
            PeerIdentity::Unix { uid: 1000, .. } => Some(ConnectionIdentity {
                role: Role::Admin,
                agent_id: None,
                label: "orchestrator".to_string(),
            }),
            // CI runner with a token.
            PeerIdentity::Tcp { .. } => {
                let token = token?;
                self.validate_ci_token(token).await
            }
            _ => None,
        }
    }
}
```

Three roles are available:
- **Admin**: Can store, delete, list secrets, and perform all lease operations.
- **Agent**: Bound to a single agent identity. Can only request/access/revoke leases. The agent field in requests is ignored — the server substitutes the bound identity.
- **Orchestrator**: Trusted to assert any agent identity per request. For systems acting on behalf of multiple agents.

## Policy Configuration

Policies can be loaded from a JSON file with `PolicyConfig::from_file()`:

```json
{
  "default_lease_terms": {
    "ttl": [900, 0],
    "renewable": false,
    "max_uses": null
  },
  "grants": [
    {
      "agent": { "Exact": "tool-git" },
      "secret": { "Exact": "github-pat" },
      "allowed_domains": ["github.com"],
      "lease_terms": {
        "ttl": [900, 0],
        "renewable": false,
        "max_uses": 10
      }
    },
    {
      "agent": { "Prefix": "ci-" },
      "secret": "Any",
      "allowed_domains": ["*.internal.example.com"],
      "lease_terms": null
    }
  ]
}
```

Agent and secret patterns support three forms:
- `{ "Exact": "name" }` — matches exactly one agent/secret
- `{ "Prefix": "ci-" }` — matches any name starting with the prefix
- `"Any"` — matches everything (use with caution)

The `lease_terms` field is optional. If `null`, the `default_lease_terms` from the top level are used. `ttl` is a `[seconds, nanoseconds]` tuple (chrono's `TimeDelta` serialization).

## Client Usage

Consumers connect via `VaultClient`:

```rust
use zerolease::client::VaultClient;
use zerolease::transport::uds::UdsConnector;

let connector = UdsConnector::new("/var/run/zerolease/vault.sock");
let mut client = VaultClient::connect(&connector).await?;

// Request a lease.
let grant = client.request_lease("my-service", "db-password", "db.internal").await?;

// Access the secret.
let secret_bytes = client.access_secret(*grant.lease_id.as_uuid(), "db.internal").await?;
let password = String::from_utf8(secret_bytes)?;

// Use the password, then let it go.
// (In practice, wrap this in a more structured pattern.)
```

For TCP clients with token auth:

```rust
use zerolease::client::VaultClient;
use zerolease::transport::tcp::TcpConnector;

let connector = TcpConnector::new("127.0.0.1:9100".parse()?, "my-bearer-token");
let mut client = VaultClient::connect_with_token(&connector, connector.token()).await?;
```

## AWS Secrets Manager Backend

If you prefer AWS to manage the encrypted secret storage (leveraging AWS's encryption, replication, and IAM):

```rust
use zerolease_store_aws_sm::AwsSecretsManagerStore;

let store = AwsSecretsManagerStore::from_env("zerolease").await?;
```

Secrets are stored as individual AWS Secrets Manager secrets under the prefix `zerolease/`. Metadata is stored in AWS tags for efficient listing. See the [AWS SM crate docs](../crates/zerolease-store-aws-sm/) for IAM permissions and configuration.

Note: the AWS SM backend provides `SecretStore` only, not `AuditLog`. Pair it with `TracingAuditLog` — AWS CloudTrail already captures Secrets Manager API calls, giving you a second audit trail.

## Monitoring and Operations

**Audit events** are emitted as structured `tracing` events at the `info` level with `target: "zerolease::audit"`. Configure your tracing subscriber to route these to your log aggregator:

```
{"timestamp":"2026-03-28T19:00:00Z","level":"INFO","target":"zerolease::audit",
 "event_id":"...", "agent":"tool-git", "event":"LeaseGranted",
 "secret_name":"github-pat", "outcome":"Success"}
```

**DEK rotation** re-encrypts all secrets under a new key. This is a `batch_update` operation — transactional in SQL backends, best-effort (but retryable) in the AWS SM backend.

**Policy reloads** are logged as `PolicyReloaded { grant_count }` audit events.
