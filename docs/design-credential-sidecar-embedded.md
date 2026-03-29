# Design: Credential Sidecar — Embedded Deployment

**Status:** Draft — revised after security review (2026-03-29)

**Date:** 2026-03-29

**Companion:** A separate design doc will cover the cloud (VM) deployment model,
where zeroclaw does NOT hold the vault and instead requests credentials from an
external service.

## Problem

AI agents access external services — Jira, GitHub, Notion, image generators —
through CLI tools and MCP servers. Today, credentials are:

- **Plaintext in config.** Written to `config.toml` or environment variables,
  readable by any process the agent spawns.
- **Unbounded lifetime.** A token set at startup is valid until the process
  dies — hours, days, indefinitely.
- **Unobservable.** No audit trail of which credential was used, when, by
  which tool, for what purpose.
- **Irrevocable.** The only way to cut off a credential is to kill the agent
  process or rotate the upstream token.

The `CredentialProvider` trait migration (zeroclaw commit `e0259516`) solved the
_interface_ problem: tools now call `acquire()` per-request and use `expose()`
with zeroize-on-drop semantics. But the backing implementation is still
`StaticProvider` — a `HashMap` seeded from config at startup. The credentials
are still plaintext, unbounded, and irrevocable.

This design replaces `StaticProvider` with a zerolease-backed provider in the
embedded (single-binary) deployment model.

## Scope

**In scope:**

- Session-scoped credential access initiated by trusted user messages
- In-process `Arc<Vault>` behind a crate feature gate (`embedded-vault`)
- Session-aware `CredentialProvider` for zeroclaw's built-in tools
- Audit logging of all credential operations
- Lease-based lifecycle with automatic revocation
- Tool-to-secret binding enforcement in policy

**Out of scope:**

- Cloud/VM deployment (separate design doc)
- Process supervisor, credential shim, fd-based delivery (VM-mode concerns;
  see "Why No Process Supervisor" below)
- MCP server launching and lifecycle management (VM-mode concern)
- Credential rotation or sync with upstream services (zerolease is not a
  secrets manager)
- OAuth-based tools (MS365Tool, LinkedInTool already have per-request
  resolution)

## Trust Model

### Honest Assessment: What Embedded Mode Provides

In the embedded model, the vault is `Arc<Vault>` in the same process as the
orchestrator. **There is no process boundary.** The orchestrator has direct
access to every method on `Vault<K, S, A>`, including methods that create
sessions, grant leases, and read raw secrets.

Session scoping in the embedded model is a **self-imposed policy** — the code
promises to only access credentials through the session API. This is a
meaningful defense-in-depth layer that protects against:

- **Bugs** — accidental credential access outside the intended scope.
- **Accidental misuse** — a tool call that requests the wrong credential.
- **Prompt injection** — the LLM cannot bypass session scoping without
  exploiting a code-level vulnerability in the orchestrator itself.
- **Auditability** — every credential access is logged, enabling forensics.

It does **NOT** protect against a **compromised orchestrator**. If an attacker
achieves arbitrary code execution in the orchestrator process (via memory
corruption, dependency supply chain attack, or a vulnerability in any loaded
crate), they have the vault. Session tokens are irrelevant — the attacker can
call `vault.access_secret()` directly.

**True credential isolation from a compromised orchestrator requires the VM
deployment model** described in `docs/design.md`, where the vault runs on a
separate host behind a network boundary.

### Session-Scoped Tokens

With that caveat established, sessions remain the fundamental unit of
authorization for the _intended_ code paths.

```
Trusted User ──message──▶ Orchestrator ──creates──▶ Session
                                                       │
                                                       ├──token──▶ Supervisor
                                                       │               │
                                                       │          vault.acquire()
                                                       │               │
                                                       │          scoped credentials
```

**Trust chain:**

1. A **trusted user** sends an incoming message (Telegram, API, CLI prompt).
2. The orchestrator authenticates the user and creates a **session**.
3. The session produces a **session token** — a random opaque handle that
   maps to session state via `HashMap` lookup within the vault.
4. The supervisor presents the session token when requesting credentials
   from the vault.
5. The vault grants credentials **scoped to the session**: bounded TTL,
   domain restrictions, use-count limits.
6. When the session ends (user disconnects, conversation completes, timeout),
   all leases issued under that session are revoked.

**Key properties:**

- **Human-initiated trust root.** Every credential access traces back to a
  specific user message. No standing privileges.
- **Session = blast radius.** In normal operation (no code-level compromise),
  credential access is limited to the scope of active sessions.
- **Single-user model.** Embedded mode serves one user at a time. There is
  no multi-user session isolation within a single process. Multi-user
  credential isolation requires the VM deployment model.

### Trust Boundaries (Embedded)

| Component                   | Trust level                                                                                                                     | Enforcement                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| The vault (in-process)      | Fully trusted. Holds credentials, enforces policy.                                                                              | N/A — the vault is the root of trust.                                           |
| The orchestrator (zeroclaw) | **Effectively fully trusted** — shares address space with vault. Session scoping is defense-in-depth, not an enforced boundary. | Self-imposed: code discipline, session API.                                     |
| CLI tools / MCP servers     | **First-party only.** Receive credentials via fd/env. Cannot outlive their supervisor. No external plugins.                      | Enforced: process isolation, process group kill, credential delivery mechanism. |
| The device (Pi / laptop)    | Trusted platform. Physical access = game over.                                                                                  | Out of scope: full-disk encryption, physical security.                          |

**Relation to `docs/design.md`:** The original zerolease design doc marks
the orchestrator as "fully trusted." The embedded model is consistent with
this — the orchestrator and vault share an address space, so they share a
trust domain. Session scoping adds defense-in-depth (auditability, lifecycle
management, blast-radius reduction for bugs) but does not create a new trust
boundary. The cloud/VM model achieves actual trust separation.

## Architecture

### Component Ownership

| Component                        | Crate                | Why                                                                                                    |
| -------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------ |
| Session management               | `zerolease`          | Sessions are a vault-level concept — the vault issues and validates session tokens.                    |
| Session-aware credential provider| `zerolease-provider` | Wraps vault access behind `CredentialProvider` trait. Carries session token for scoped lease requests. |
| Tool registry wiring             | `zeroclaw`           | Connects `build_credential_provider()` to the vault. Feature-gated on `embedded-vault`.                |

### Feature Gate: `embedded-vault`

```toml
# zeroclaw/Cargo.toml
[features]
embedded-vault = ["zerolease/vault", "zerolease/sqlite-store", "zerolease/keychain"]
```

**With `embedded-vault`:**

- Zeroclaw constructs `Arc<Vault<KeychainSource, RusqliteStore, RusqliteAuditLog>>`
  at startup.
- `build_credential_provider()` returns a session-aware `ZeroleaseProvider`
  backed by this in-process vault.
- Single binary, no external services required. Suitable for Raspberry Pi,
  laptop, air-gapped environments.

**Without `embedded-vault`:**

- Zeroclaw depends only on `zerolease-types` (for `SecretName`, `LeaseGrant`,
  etc.) and `zerolease-provider`.
- `build_credential_provider()` connects to an external credential service
  (details in the cloud design doc).
- No vault code, no crypto dependencies compiled in.

### Credential Flow: Built-in Tools

In embedded mode, zeroclaw's tools are built-in Rust implementations
(`impl Tool`) that call `CredentialProvider::acquire()` directly. There
are no child processes, no fd delivery, no credential shim. The credential
exists only within an `expose()` closure and is zeroized when the guard
drops.

```
Trusted User ──message──▶ Zeroclaw
                               │
                          create_session(user, policy)
                               │
                          session token stored in HashMap
                               │
                          LLM decides: call jira tool
                               │
                          JiraTool::execute()
                               │
                          credential_provider.acquire(CredentialRequest {
                              secret_name: "jira-pat",
                              target_domain: "*.atlassian.net",
                              agent_id: "tool-jira",
                              session_token,               // NEW: scoped to session
                          })
                               │
                          vault validates:
                            ✓ session is active
                            ✓ tool-to-secret binding allows jira → jira-pat
                            ✓ domain scope matches
                            ✓ max_concurrent_leases not exceeded
                               │
                          lease granted (TTL=60s)
                               │
                          guard.expose(|token| {
                              // token is &str, lives only in this closure
                              http_client.basic_auth(&email, Some(token))
                                  .send()
                          })
                               │
                          guard dropped → credential zeroized
                          lease revoked (or expires via TTL)
                          audit: SecretAccessed { tool: "jira", domain: "*.atlassian.net", duration: 0.3s }
```

**Why this is secure by construction:**

1. The credential never exists as a named binding. It's a closure argument
   (`&str`) that cannot be stored, cloned, or passed elsewhere.
2. The `CredentialGuard` is not `Clone`, not `Serialize`, and redacts in
   `Debug`. You cannot accidentally persist it.
3. The lease is revoked when the guard drops — automatic, deterministic.
4. The session token scopes what the tool can request. A prompt injection
   that tricks the LLM into calling the Jira tool with a GitHub credential
   request is rejected by the policy engine's tool-to-secret binding.
5. No child processes means no fork escape, no fd inheritance, no env var
   leakage, no process group management.

### Why No Process Supervisor in Embedded Mode

The process supervisor (credential shim, fd delivery, process group
isolation) exists to bring *external* processes closer to the security
properties that built-in tools already have natively. In embedded mode,
all tools are built-in Rust code — the `expose()` closure pattern provides
strictly stronger guarantees than any subprocess-based delivery mechanism:

| Property                    | Built-in (`expose()`)           | Subprocess (fd/env) |
| --------------------------- | ------------------------------- | ------------------- |
| Credential lifetime         | Microseconds (closure scope)    | Entire process life |
| Credential location         | Stack frame only                | Env var or fd       |
| Code you control            | 100% (your Rust)                | 0% (opaque binary)  |
| Fork escape risk            | N/A                             | Yes (env var path)  |
| Process isolation needed    | No                              | Yes                 |
| Audit granularity           | Per-API-call                    | Per-lease (coarse)  |

The supervisor, shim, and fd plumbing are **VM-mode concerns** — needed
when zeroclaw orchestrates QEMU VMs running Claude Code with external
plugins. That infrastructure will be designed in the VM deployment doc.

**Embedded mode does not support MCP servers.** If a capability is needed,
implement it as a built-in `impl Tool` with `acquire()`/`expose()`. This
inherits every security property for free.

### Session Lifecycle

```
┌──────────────────────────────────────────────────────┐
│                    SESSION                           │
│                                                      │
│  Created: trusted user sends message                 │
│  Token:   random opaque handle, HashMap lookup       │
│  Scope:   which credentials may be requested         │
│  TTL:     max session duration (configurable)        │
│                                                      │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐               │
│  │ Lease 1 │  │ Lease 2 │  │ Lease 3 │   ...         │
│  │ jira    │  │ github  │  │ notion  │               │
│  │ 60s TTL │  │ 60s TTL │  │ 60s TTL │               │
│  └─────────┘  └─────────┘  └─────────┘               │
│                                                      │
│  Ends: user disconnects / conversation done /        │
│        timeout / explicit revocation                 │
│                                                      │
│  On end: all child leases revoked,                   │
│          audit summary emitted                       │
└──────────────────────────────────────────────────────┘
```

**Session creation policy** determines which credentials a session may access.
This is configured per-user or per-channel:

```toml
# Example: zerolease session policy
[[session_policy]]
user = "ceej"
channel = "telegram"
max_session_duration = "1h"    # absolute hard cap, non-renewable
max_concurrent_leases = 5
max_renewals_per_lease = 3     # prevents infinite renewal

# Tool-to-secret bindings: each built-in tool can only access its bound
# secrets. The vault's policy engine enforces this at acquire() time.

[[tool_credential_binding]]
tool = "jira"
secrets = ["jira-pat"]
domains = ["*.atlassian.net"]

[[tool_credential_binding]]
tool = "github"
secrets = ["github-pat"]
domains = ["api.github.com", "github.com"]

[[tool_credential_binding]]
tool = "notion"
secrets = ["notion-key"]
domains = ["api.notion.com"]
```

Tool-to-secret bindings prevent a confused-deputy attack: even if a prompt
injection tricks the LLM into calling a tool with the wrong credential
request, the policy engine rejects it at `acquire()` time. No env vars
or delivery methods are needed — built-in tools receive credentials via
the `expose()` closure, never as materialized values.

## Security Considerations

### What Embedded Mode Provides

Embedded mode provides **secure-by-construction credential handling,
auditability, and defense-in-depth** against bugs and prompt injection.

- **Credential never materialized.** The `expose()` closure pattern means
  credentials exist only as closure arguments (`&str`) on the stack. They
  cannot be stored, logged, serialized, or passed to another function.
  This is strictly stronger than any subprocess-based delivery.
- **Lateral movement prevention.** Tool-to-secret bindings ensure a tool
  invoked for Jira cannot request the GitHub token, even within the same
  session. Enforced at `acquire()` time by the vault's policy engine.
- **Bounded access windows.** `max_session_duration` + `max_renewals_per_lease`
  \+ lease TTL = hard upper bound on credential accessibility.
- **Full audit trail.** Every lease acquisition, access, and revocation
  produces an audit event tied to session ID, user, tool, and timestamp.
- **Defense against prompt injection.** A prompt injection attack can only
  operate within the session's credential scope and tool-to-secret bindings.
  It cannot create new sessions (requires trusted user authentication),
  access credentials outside the session policy, or request credentials not
  bound to the tool being invoked.
- **No subprocess attack surface.** No child processes, no fd inheritance,
  no env var leakage, no process group escape, no fork bombs. All tool
  code runs in-process under the orchestrator's control.

### What Embedded Mode Does NOT Provide

- **Isolation from a compromised orchestrator.** The vault and orchestrator
  share an address space. Arbitrary code execution in the orchestrator =
  full vault access. This requires the VM deployment model.
- **Network-layer enforcement.** No proxy, no iptables, no egress filtering.
  A bug in a built-in tool could send a credential to the wrong endpoint
  during the lease window.
- **Protection against malicious use of allowed APIs.** A tool with a valid
  Jira lease can create/delete/modify Jira issues. Domain-scoping prevents
  _which_ service, not _what actions_.
- **Protection against bugs in built-in tools.** A coding error in a
  built-in tool could leak credential material (e.g., including it in
  a log message or error response fed back to the LLM). The `expose()`
  closure makes this harder but not impossible.

### Concrete Attack Scenarios

These scenarios are documented for threat modeling. Each has a corresponding
mitigation (implemented or planned).

**Scenario 1: Prompt injection — confused deputy.**
A Jira issue body contains prompt injection text. The injected prompt
tricks the LLM into calling the HTTP request tool with the Jira credential
to post data to an attacker-controlled endpoint.

_Mitigations:_ Tool-to-secret binding — the HTTP request tool has no
credential bindings (or its own, separate bindings). The vault rejects
the `acquire()` call because "jira-pat" is not bound to "http_request".
The LLM cannot override policy.

**Scenario 2: Prompt injection — credential in tool output.**
A prompt injection causes the LLM to call a tool in a way that includes
credential material in the tool's return value (e.g., "print the auth
header you just used"). The credential enters the LLM context and may be
exfiltrated in a subsequent tool call to an allowed domain.

_Mitigations:_ The `expose()` closure pattern makes this harder — the
credential is a closure argument, not a variable the tool can easily
include in its output. However, a built-in tool could be written with a
bug that captures and returns the credential. Short lease TTLs limit the
window. Code review of built-in tools is the primary defense.

**Scenario 3: Bug in built-in tool leaks credential.**
A coding error in a built-in tool stores the credential in a struct
field, logs it, or includes it in an error message. The credential
persists beyond the `expose()` closure's intended scope.

_Mitigations:_ The `CredentialGuard` is not `Clone` and not `Serialize`.
The credential is `&str` (borrowed), so storing it requires an explicit
`.to_string()` — a code smell detectable in review. Lease TTL bounds
the credential's validity. Audit log records every access. This is
fundamentally a code quality issue — the type system raises the bar but
cannot prevent a determined (or careless) developer from copying the
value.

**Scenario 4: Lease renewal as infinite access.**
A long conversation keeps renewing leases, providing continuous credential
access despite short TTLs.

_Mitigation:_ `max_renewals_per_lease` (default: 3) and
`max_session_duration` (absolute hard cap). These are enforced by the
vault, not the tool code — a bug in a tool cannot extend its own lease
beyond the policy limits.

**Scenario 5: Session outlives user intent.**
The user walks away from a conversation. The session remains active
(no explicit disconnect), and a prompt injection from earlier-loaded
content continues to issue tool calls using the session's credentials.

_Mitigation:_ `max_session_duration` provides an absolute hard cap.
The session expires regardless of activity. For the embedded model
(single user, trusted device), this is sufficient. The VM model adds
network-layer enforcement for stronger guarantees.

### Mitigations Summary

| Mitigation                                     | Status   | Priority |
| ---------------------------------------------- | -------- | -------- |
| `expose()` closure credential delivery         | Existing | P0       |
| Tool-to-secret binding in policy               | Designed | P0       |
| Hard-cap session/lease lifetimes               | Designed | P0       |
| Fail closed on vault init failure              | Designed | P0       |
| Audit log integrity (hash-chained entries)     | Planned  | P2       |

**Not applicable to embedded mode** (all are VM-mode concerns):

- **Fd-based credential delivery / credential shim.** Built-in tools use
  `expose()` closure — strictly stronger than any subprocess delivery.
- **Process group isolation.** No child processes in embedded mode.
- **Executable allowlisting.** No external binaries executed.
- **Core dump prevention (`prctl`).** Marginal; the DEK in a core dump
  is the real risk, and an attacker with core dump access has broader
  filesystem access. Consider for VM mode.

**Removed after security review (2026-03-29):**

- **HMAC-SHA256 session tokens / `mlock` / HKDF key derivation.** In
  embedded mode, the session token never leaves the process. A random
  token with `HashMap` lookup provides identical security. HMAC tokens
  are appropriate for the VM model where tokens cross a network boundary.
- **Rate limiting on session creation.** The only session creator is the
  orchestrator, gated on authenticated user messages. No threat model.
- **Credential output redaction.** Pattern-based scanning provides false
  confidence. Deferred — build only if real-world tool output reveals need.
- **Policy file integrity signing.** Incoherent without signing the binary,
  SQLite database, and keychain entry. Physical filesystem access is game
  over in embedded mode.

### Fail-Closed Behavior

If `embedded-vault` is configured but vault construction fails (keychain
unavailable, SQLite corruption, missing DEK), `build_credential_provider()`
MUST return an error. It MUST NOT silently fall back to `StaticProvider`.

Fallback to `StaticProvider` (plaintext credentials, no sessions, no leases,
no audit) is a **fail-open** behavior that defeats every security property
in this design. If an operator wants plaintext fallback, they must
explicitly opt in:

```toml
[zerolease]
enabled = true
fallback = "static"  # explicit opt-in, logged as warning
```

Without `fallback = "static"`, vault initialization failure is fatal.

### Session Token Specification

In the embedded model, the session token is a **random opaque handle**:

- 128-bit random value generated via `OsRng`.
- Stored in a `HashMap<SessionToken, Session>` within the vault.
- Zeroized when the session ends.
- Child processes never receive the session token — they receive credentials
  via fd, not the token itself.

**Why not HMAC-SHA256?** The token never leaves the process. The creator
and validator are the same code. There is no network boundary and no
untrusted party presenting tokens. A `HashMap` lookup provides identical
security with no crypto dependencies, no key derivation ceremony, and
fewer things to get wrong. The VM deployment model — where tokens cross
a network boundary and stateless validation matters — will define its own
token format appropriate to that trust model.

### Audit Log Integrity

Each audit entry includes a SHA-256 hash of the previous entry, forming
a hash chain. Tampering with or deleting entries in the SQLite file is
detectable by verifying the chain with `verify_audit_chain()`.

**What this protects against:** Post-hoc forensic tampering — someone
editing the SQLite audit database after the fact to cover tracks.

**What this does NOT protect against:** A compromised orchestrator
fabricating entries in real time. The hash chain is computed by the same
process that writes entries. In-process integrity requires replication to
a remote append-only store (syslog, S3 with object lock, etc.) — a
deployment concern, not a code requirement.

The SQLite audit database uses WAL mode and restrictive filesystem
permissions (`0600`, owned by the zeroclaw process user).

### Resolved Questions (2026-03-29)

1. **Credential output redaction.** Deferred. Pattern-based scanning
   provides false confidence and doesn't catch non-standard formats. Build
   only if real-world tool output demonstrates the need.

2. **Re-authentication for long sessions.** Not implemented for now.
   `max_session_duration` provides a hard cap. Re-authentication adds
   friction to the primary use case (long-running autonomous sessions).
   Revisit if prompt injection attacks demonstrate session-extending
   behavior in practice.

3. **Sandboxing child processes.** Deferred to VM model. High cost,
   platform-specific, limited value when all tools are first-party.

4. **Policy file integrity.** Skipped. Incoherent without signing the
   entire filesystem. Physical access to an embedded device is game over.

5. **Session token format.** Random 128-bit tokens with `HashMap` lookup.
   HMAC-SHA256 is appropriate for the VM model (network boundary, stateless
   validation). Not for embedded (same-process, no untrusted presenter).

6. **Multi-user sessions.** Embedded mode is single-user. No multi-user
   session isolation within a single process. Multi-user requires the VM
   deployment model.

## Implementation Phases

### Phase 1: Session Infrastructure (zerolease)

- Add `Session` type: ID, user, channel, created_at, expires_at, policy
- Add `SessionToken` type: random 128-bit opaque handle, `HashMap` lookup
- Session token zeroized on session end
- Add session creation/validation/revocation to vault API
- Add session policy configuration with `max_session_duration`,
  `max_renewals_per_lease`, `max_concurrent_leases`
- Add tool-to-secret binding schema and policy enforcement
- Extend `CredentialRequest` to carry optional `SessionToken`
- Vault enforces session scope on lease requests when token is present
- Audit log hash chain (SHA-256, tamper-evident for offline forensics)
- Tests: session lifecycle, token validation, expiry, revocation,
  tool-to-secret binding enforcement, audit chain verification

### Phase 2: Zeroclaw Integration

- Feature gate `embedded-vault` in `Cargo.toml`
- In-process vault construction at startup (keychain + sqlite)
- Wire `build_credential_provider()` to return session-aware
  vault-backed provider; return error (not `StaticProvider`)
  if vault init fails
- Session creation on incoming user message
- Session token threaded through tool execution context to provider
- Session revocation on conversation end / disconnect / timeout
- Disable MCP server support when `embedded-vault` is active (all
  tools must be built-in; MCP servers bypass `expose()` guarantees)
- Tests: end-to-end with real vault, session-to-tool-call flow,
  fail-closed behavior, tool-to-secret binding rejection

## Relation to Existing Code

| Existing code                                               | Role in this design                                                                                                                                                            |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `CredentialProvider` trait (`zerolease-provider`)           | Extended: `CredentialRequest` gains optional `SessionToken` field. Tools continue to call `acquire()`/`expose()` — the session token is threaded through by the orchestrator. |
| `StaticProvider` (`zerolease-provider`)                     | Remains when `embedded-vault` is off and no external service is configured. NOT used as silent fallback when vault init fails — fail-closed behavior requires explicit opt-in. |
| `build_credential_provider()` (zeroclaw `src/tools/mod.rs`) | Extended: when `embedded-vault` is on, constructs session-aware `ZeroleaseProvider` backed by in-process vault. Returns error on vault init failure.                           |
| `Vault<K, S, A>` (`zerolease`)                              | Used directly in-process. New: session-aware lease requests, hash-chained audit entries.                                                                                       |
| ADR-004 `ClientId` (zeroclaw)                               | Session ID composes with `ClientId` — a session is initiated by a client, and the client's identity is part of the session's trust root.                                       |
| `SecurityPolicy` (zeroclaw)                                 | Orthogonal. Security policy governs what the _agent_ may do; session policy governs what _credentials_ the agent may access via tool-to-secret bindings.                       |

## Values

In priority order, when design decisions conflict:

1. **Secure by construction.** The `expose()` closure pattern means
   credentials cannot escape their intended scope without an explicit
   coding error. Prefer compile-time guarantees over runtime enforcement.
2. **Honest about guarantees.** Embedded mode provides auditability and
   defense-in-depth against bugs and prompt injection. It does not provide
   credential isolation from a compromised orchestrator. Don't claim what
   you can't enforce.
3. **Zero-trust by default.** Per-request credential resolution. Never
   per-process or per-startup. Fail closed, never open.
4. **Observable.** Every credential access produces an audit event.
   Silent failures are bugs. Audit integrity is verifiable.
5. **Incrementally adoptable.** One tool at a time. The feature gate means
   zero cost when not used.
6. **Simple over clever.** Flat policy files, session-scoped leases, no
   subprocess machinery, no custom protocol, no tool modifications.
