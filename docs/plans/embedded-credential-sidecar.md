# Plan: Embedded Credential Sidecar

**Date:** 2026-03-29
**Design doc:** [design-credential-sidecar-embedded.md](../design-credential-sidecar-embedded.md)
**Repos:** zerolease (phase 1), zeroclaw (phase 2)

## Starting Point

| Component | Status | Location |
|-----------|--------|----------|
| `Vault<K, S, A>` with leases, policy, AEAD crypto | Done | `zerolease` core |
| `CredentialProvider` trait + `CredentialGuard` | Done | `zerolease-provider` |
| `StaticProvider` (current bridge) | Done | `zerolease-provider` |
| `ZeroleaseProvider` (vault-backed) | Done | `zerolease-provider` (feature `vault`) |
| `TokenAuthenticator` (SHA-256 hashed tokens) | Done | `zerolease/src/auth.rs` |
| `provision` command (acquire + write + exit) | Done | `zerolease-agent` (VM-specific) |
| Zeroclaw `build_credential_provider()` wiring | Done | `zeroclaw/src/tools/mod.rs` |
| Built-in tools using `acquire()`/`expose()` pattern | Done | zeroclaw (commit `e0259516`) |
| `zerolease-types` lightweight crate | Done | `zerolease-types` |

## Key Architectural Decision

Embedded mode uses **only built-in tools** (in-process Rust `impl Tool`).
No MCP servers, no subprocess launching, no credential shim, no fd delivery.

Built-in tools call `acquire()`/`expose()` directly. The credential exists
only as a closure argument (`&str`) and is zeroized when the guard drops.
This is **secure by construction** — strictly stronger than any subprocess-
based credential delivery.

The process supervisor, credential shim, fd delivery, and MCP server
lifecycle management are **VM-mode concerns** for the separate VM
deployment design. They are not needed here.

## Dependency Graph

```
Phase 1 (sessions, policy, vault API, audit)
    |
    \---> Phase 2 (zeroclaw integration)
```

Two phases. Phase 1 is pure zerolease. Phase 2 is zeroclaw.

---

## Phase 1: Session Infrastructure (zerolease)

Introduces sessions as a first-class vault concept and tool-to-secret
binding in policy.

### 1a. Session types and storage

- [ ] `Session` struct: `SessionId`, user, channel, `created_at`, `expires_at`, policy reference
- [ ] `SessionToken` struct: random 128-bit opaque handle (`[u8; 16]` from `OsRng`)
- [ ] `HashMap<SessionToken, Session>` in vault, behind `RwLock`
- [ ] `Zeroize` impl on `SessionToken`

### 1b. Session policy schema

- [ ] `SessionPolicy` struct: `max_session_duration`, `max_concurrent_leases`, `max_renewals_per_lease`
- [ ] `ToolCredentialBinding` struct: tool name -> allowed secrets + domains
- [ ] Policy loading from TOML (embedded format) alongside existing JSON policy
- [ ] Policy validation: reject overlapping bindings, warn on overly broad grants
- [ ] Enforcement: vault rejects lease requests that violate tool-to-secret bindings

### 1c. Session lifecycle on the vault

- [ ] `vault.create_session(user, channel, policy) -> SessionToken`
- [ ] `vault.validate_session(token) -> Session`
- [ ] `vault.revoke_session(session_id)` -- revokes all child leases
- [ ] Session expiry background task (reuse existing lease GC pattern)
- [ ] Lease requests optionally carry `SessionToken` -- vault validates session is active and lease is within session scope
- [ ] `max_session_duration` enforced as absolute non-renewable cap
- [ ] `max_renewals_per_lease` enforced on `renew_lease`

### 1d. CredentialRequest extension

- [ ] Add optional `SessionToken` field to `CredentialRequest` (in `zerolease-types` or `zerolease-provider`)
- [ ] Add `tool_name` field to `CredentialRequest` (for tool-to-secret binding enforcement)
- [ ] When session token is present, vault validates: session active, tool-to-secret binding allows this tool to access this secret, domain scope matches
- [ ] When session token is absent, existing behavior unchanged (backward compatible)

### 1e. Audit log integrity

- [ ] Add hash chain: each audit entry includes `prev_hash` (SHA-256 of previous entry)
- [ ] `verify_audit_chain()` function: walk chain, verify hashes
- [ ] Applies to `RusqliteAuditLog` initially; trait extension for other backends
- [ ] SQLite WAL mode + restrictive file permissions (`0600`)
- [ ] Note: hash chain detects offline tampering only, not in-process fabrication

### 1f. Tests

- [ ] Session create / validate / revoke lifecycle
- [ ] Token lookup: valid token returns session, random bytes rejected
- [ ] Tool-to-secret binding enforcement (jira can get jira-pat, cannot get github-pat)
- [ ] Lease request rejected when session expired
- [ ] Session revocation cascades to child leases
- [ ] Audit chain integrity verification (valid chain, tampered entry detected)
- [ ] `max_session_duration` enforcement
- [ ] `max_renewals_per_lease` enforcement
- [ ] CredentialRequest with session token: scoped correctly
- [ ] CredentialRequest without session token: backward compatible

---

## Phase 2: Zeroclaw Integration

Wires the zerolease session infrastructure into the zeroclaw tool registry
and message handling pipeline.

### 2a. Feature gate

- [ ] `embedded-vault` feature in zeroclaw `Cargo.toml`
- [ ] Feature pulls in: `zerolease` (vault, sqlite-store, keychain features)
- [ ] Without feature: only `zerolease-types` + `zerolease-provider`
- [ ] Conditional compilation throughout: `#[cfg(feature = "embedded-vault")]`

### 2b. Vault construction at startup

- [ ] Construct `Arc<Vault<KeychainSource, RusqliteStore, RusqliteAuditLog>>` when feature active
- [ ] **Fail-closed**: vault init failure -> startup error, NOT fallback to `StaticProvider`
- [ ] `StaticProvider` fallback requires explicit `fallback = "static"` in config + audit warning
- [ ] Vault DB path configurable (default: `~/.zeroclaw/vault.db`)
- [ ] Audit DB path configurable (default: `~/.zeroclaw/audit.db`)

### 2c. Session creation on incoming messages

- [ ] Trusted user message (Telegram, API) -> `vault.create_session()`
- [ ] Map user identity to session policy from zeroclaw config
- [ ] Session token threaded through tool execution context to `CredentialProvider`
- [ ] Session revocation on conversation end / user disconnect / timeout
- [ ] Tie session lifecycle to `ClientId` from ADR-004

### 2d. Disable MCP when embedded-vault is active

- [ ] When `embedded-vault` feature is active, MCP server configuration is rejected at startup
- [ ] Log clear error: "MCP servers are not supported in embedded-vault mode — use built-in tools"
- [ ] All credential-bearing tools must be built-in `impl Tool` using `acquire()`/`expose()`

### 2e. Tests

- [ ] End-to-end: user message -> session -> tool call -> acquire() -> expose() -> lease revocation
- [ ] Fail-closed: vault init failure -> startup error
- [ ] Session lifecycle tied to conversation lifecycle
- [ ] Tool-to-secret binding rejection at vault layer
- [ ] `StaticProvider` fallback only with explicit config
- [ ] MCP server config rejected when embedded-vault is active

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Phase 1 session model has design flaws | Cascades to Phase 2 | Session types are pure data, testable in isolation; security review completed |
| `CredentialRequest` extension breaks existing consumers | Backward compatibility | New fields are optional; absent token = existing behavior |
| Bug in built-in tool leaks credential from `expose()` closure | Credential in LLM context | Type system makes this hard (not Clone, not Serialize, `&str` borrow); code review is primary defense |
| Zeroclaw feature gate creates compile-time divergence | Untested code paths | CI matrix: build + test with and without `embedded-vault` feature |

## Success Criteria

- [ ] A trusted user message creates a session with bounded lifetime
- [ ] A built-in tool's `acquire()` is scoped to the active session
- [ ] Tool-to-secret bindings prevent credential cross-contamination
- [ ] Session expiry revokes all child leases
- [ ] Vault init failure prevents startup (fail-closed)
- [ ] Every credential operation produces a hash-chained audit event
- [ ] MCP servers are rejected when embedded-vault is active
- [ ] The entire system works on a Raspberry Pi as a single binary
