# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

zerolease is a lightweight, agent-aware credential vault with lease-based access control, written in Rust. It's designed for AI agent orchestration environments where untrusted tools need time-bounded, scope-limited access to credentials. Supports deployment on developer laptops (Unix domain socket + OS keychain), QEMU VMs (TCP + token auth), and VM-isolated environments (vsock + AWS KMS).

**Status**: Early development — core traits, types, and multiple backend implementations are functional. The workspace includes storage backends for rusqlite, PostgreSQL, and AWS Secrets Manager.

## Build Commands

```bash
cargo build                    # Build workspace (core + rusqlite store)
cargo test --workspace         # Run all workspace tests
cargo clippy --workspace       # Lint all workspace members
cargo fmt                      # Format

# Excluded crate (sqlx/rusqlite conflict):
cargo build --manifest-path crates/zerolease-store-postgres/Cargo.toml
cargo clippy --manifest-path crates/zerolease-store-postgres/Cargo.toml --all-targets
```

Requires Rust edition 2024.

## Workspace Structure

| Crate | Location | In workspace? |
|-------|----------|---------------|
| `zerolease` (core) | `.` | yes |
| `zerolease-provider` | `crates/zerolease-provider` | yes |
| `zerolease-store-rusqlite` | `crates/zerolease-store-rusqlite` | yes |
| `zerolease-store-aws-sm` | `crates/zerolease-store-aws-sm` | yes |
| `zerolease-store-postgres` | `crates/zerolease-store-postgres` | **excluded** (sqlx conflict) |

The postgres crate is excluded because sqlx and rusqlite both link `libsqlite3-sys`. Build/test it separately with `--manifest-path`.

## Architecture

The vault is a generic struct `Vault<K, S, A>` parameterized over three backend traits, allowing compile-time selection of deployment configuration:

| Trait | Purpose | Implementations |
|-------|---------|-----------------|
| `KeySource` | Master key (DEK) management | OS keychain, AWS KMS, env var |
| `SecretStore` | Encrypted secret persistence | rusqlite, PostgreSQL, AWS Secrets Manager |
| `AuditLog` | Append-only event log | `TracingAuditLog` (core), rusqlite, PostgreSQL |

Transport is a separate abstraction (`VaultListener`/`VaultConnector`) over Unix domain sockets, TCP, and vsock. Authentication is pluggable via the `Authenticator` trait.

### Request Flow

Agent -> Transport -> Handshake (ClientHello/ServerHello) -> Authenticator (PeerIdentity + token -> ConnectionIdentity) -> Vault -> PolicyEngine (deny-by-default, first-match) -> SecretStore (encrypted blob) -> decrypt with DEK -> create Lease + LeaseGuard -> AuditLog -> return LeaseGrant to agent.

### Key Design Decisions

- **Newtype IDs**: `SecretId`, `AgentId`, `LeaseId`, `SecretName`, `DomainScope` are all newtypes preventing accidental misuse at compile time. All UUID-based IDs use v7 (time-ordered).
- **Zeroize-on-drop**: Secret values use `SecretString`/`Zeroize`. `LeaseGuard` is not Clone, not Serialize, and redacts in Debug output.
- **Envelope encryption**: KMS-backed deployments use a local DEK encrypted by KMS, avoiding a KMS round-trip per secret operation.
- **DomainScope restriction**: Credentials are scoped to target domains (exact match, wildcard subdomain `*.example.com`, or localhost:port).
- **Policy model**: Deny-by-default, flat grant list, first-match-wins. Designed for auditability.
- **Transport↔Auth separation**: Transports provide `PeerIdentity` (UID/PID, CID, or token hash). The `Authenticator` maps this to `ConnectionIdentity` (role + agent binding). TCP transports include a bearer token in `ClientHello`.
- **Storage↔Audit decoupling**: `SecretStore` and `AuditLog` are independent — pick each backend separately. AWS SM provides only `SecretStore`; pair with `TracingAuditLog`.

### Feature Flags (core crate)

- `vsock` — enables tokio-vsock for VM communication (Linux only)
- `kms` — enables AWS KMS key source

### Code Quality Principles

- Idiomatic Rust. Clippy clean. Experienced Rust developers should feel at home.
- Prefer well-tested, well-established dependencies from known community members.
- Tidy, efficient code. Well-named variables and functions. Readable by humans and agents.
- Memory and CPU efficient — no needless clones. Compatible with the zeroclaw philosophy.
- Use Rust types to prevent bugs (newtypes, enums, exhaustive matching).
- A little macro-writing goes a long way for readability (`col!`, `parse_params!`, `json_response!`).
