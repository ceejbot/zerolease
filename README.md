# zerolease

A credential vault for AI agent environments. Stores secrets encrypted at rest and grants access through leases: time-bounded, scope-restricted handles that expire automatically and can be revoked at any time.

[![Tests](https://github.com/ceejbot/zerolease/actions/workflows/test.yaml/badge.svg)](https://github.com/ceejbot/zerolease/actions/workflows/test.yaml) [![audit-dependencies](https://github.com/ceejbot/zerolease/actions/workflows/audit.yaml/badge.svg)](https://github.com/ceejbot/zerolease/actions/workflows/audit.yaml) [![codecov](https://codecov.io/github/ceejbot/zerolease/graph/badge.svg?token=XGD9GA2H66)](https://codecov.io/github/ceejbot/zerolease)

## Why

When AI agents use tools that need credentials — API tokens, SSH keys, database passwords — giving the agent direct access to the credential is dangerous. An agent with a raw GitHub PAT can use it against any endpoint, keep it indefinitely, and leak it to any tool it invokes.

`zerolease` sits between agents and credentials. Instead of handing out a token, the vault issues a _lease_: a handle that grants access to a specific credential, for a specific domain, for a limited time. A Jira PAT can only be injected into requests to `*.atlassian.net`. A GitHub token expires after 15 minutes. Every access is logged.

## Design

The vault is a Rust library that agents connect to over Unix domain sockets (developer machines), TCP with token auth (QEMU VMs), or vsock (Firecracker). Credentials never leave the vault as plaintext over a network — the transport is local to the host or hypervisor.

**Encryption.** Secrets are encrypted at rest using `AES-256-GCM` or `XChaCha20-Poly1305` (configurable per secret, with algorithm migration support). The data encryption key is managed by a pluggable key source: OS keychain for developer machines, AWS KMS for production, or an environment variable for CI.

**Policy.** Access is deny-by-default. A flat list of grant rules specifies which agents can access which secrets for which domains. First match wins. The policy format is intentionally simple — easier to audit than a policy language.

**Leases.** Every credential access goes through a lease. Leases have a TTL, an optional use count, and a list of allowed target domains. The vault tracks active leases in memory, enforces per-agent caps, and garbage-collects expired ones. Secret values are zeroized from memory when the lease guard is dropped.

**Authentication.** Connections are authenticated via a pluggable `Authenticator` trait that maps transport-level peer identity to roles. Three roles exist: Admin (full access), Agent (bound to a single identity, can only use leases), and Orchestrator (trusted to assert agent identity per request). TCP transports present a bearer token in the handshake; UDS/vsock rely on OS-level identity.

**Audit.** Every lease grant, secret access, revocation, and policy denial is logged. The core crate includes `TracingAuditLog` (emits structured `tracing` events for external log aggregation). Queryable backends are available in the store crates.

## Workspace

zerolease is a Cargo workspace. The core crate defines traits; storage and provider crates are chosen at compile time.

| Crate | Purpose |
|-------|---------|
| **zerolease** | Core: `Vault`, traits (`SecretStore`, `AuditLog`, `KeySource`), transports, policy engine |
| **zerolease-store-rusqlite** | SQLite storage via rusqlite — `SecretStore` + `AuditLog` |
| **zerolease-store-postgres** | PostgreSQL storage via sqlx — `SecretStore` + `AuditLog` |
| **zerolease-store-aws-sm** | AWS Secrets Manager — `SecretStore` only (pair with `TracingAuditLog`) |
| **zerolease-provider** | `CredentialProvider` trait for AI agent tool integration |

Pick a store crate and an audit backend independently:

- **Developer laptop:** rusqlite store + `RusqliteAuditLog` (single file, zero config)
- **Cloud VMs:** AWS SM store + `TracingAuditLog` (logs to stdout → CloudWatch)
- **Shared infra:** PostgreSQL store + `PostgresAuditLog`

## Transports

| Transport | Use case | Identity source |
|-----------|----------|-----------------|
| **Unix domain socket** | Developer machines, local processes | OS peer credentials (UID/PID) |
| **TCP + token** | QEMU VMs via host-forwarded ports | Bearer token in `ClientHello` handshake |
| **vsock** | Firecracker/QEMU via virtio | Guest CID (Linux only, feature `vsock`) |

TCP listeners bind to `127.0.0.1` only. The `TokenAuthenticator` maps pre-registered tokens to connection identities. Raw tokens are never stored — only SHA-256 hashes.

## Quick start

```bash
# Generate a data encryption key
export ZEROLEASE_KEY=$(openssl rand -hex 32)

# Run the example (direct vault API, no server)
cargo run --example basic_vault
```

## Building

Requires Rust edition 2024.

```bash
cargo build                    # core + rusqlite store
cargo test --workspace         # run workspace tests
cargo clippy --workspace       # lint

# Excluded crate (built separately due to sqlx/rusqlite conflict):
cargo build --manifest-path crates/zerolease-store-postgres/Cargo.toml
```

### Feature flags (core crate)

| Flag    | Default | What it enables |
|---------|---------|-----------------|
| `vsock` | No      | vsock transport for Firecracker/QEMU VMs (Linux only) |
| `kms`   | No      | AWS KMS envelope encryption key source |

## Testing

```bash
# Workspace tests
cargo test --workspace

# PostgreSQL integration tests (requires running Postgres)
cargo test --manifest-path crates/zerolease-store-postgres/Cargo.toml \
  --run-ignored ignored-only --test-threads=1

# AWS Secrets Manager tests (requires credentials + IAM permissions)
ZEROLEASE_SM_TEST_PREFIX=zerolease_test_ \
  cargo test -p zerolease-store-aws-sm --run-ignored ignored-only --test-threads=1

# AWS KMS integration tests
cargo test -p zerolease --features kms -E 'test(keysource::kms)' --run-ignored ignored-only

# OS keychain integration test
cargo test -p zerolease keysource::keychain -- --ignored
```

## Wire protocol

JSON over length-prefixed frames (4-byte big-endian length + payload). Each connection begins with a `ClientHello`/`ServerHello` handshake (TCP clients include a bearer token). Requests carry a UUID v7 identifier for correlation. Eight methods: `store_secret`, `request_lease`, `access_secret`, `revoke_lease`, `revoke_all_for_agent`, `list_secrets`, `renew_lease`, `delete_secret`.

## Security

- Secret material zeroized on drop (`Zeroize`, `SecretString`, `Zeroizing<Vec<u8>>`)
- Decryption errors are generic (no information leakage)
- Domain scope matching rejects edge cases (empty subdomains, path traversal)
- Policy engine is deny-by-default; empty prefix patterns are warned
- Lease renewal capped at 24 hours; per-agent lease count capped
- SQL injection prevented by parameterized queries
- Debug impls redact secret material
- Role-based access control prevents agents from calling admin operations
- Agent identity bound at transport level, not self-asserted
- Auth tokens stored as SHA-256 hashes, never in plaintext
- TCP listener binds localhost only

## Status

Early development. Trait definitions and core types are stable. Concrete backend implementations are functional. Integration-level documentation and a standalone server binary are planned.

## License

Apache-2.0
