# Design: Credential Sidecar — Embedded Deployment

**Status:** Draft — revised after internal security audit, awaiting human review

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
*interface* problem: tools now call `acquire()` per-request and use `expose()`
with zeroize-on-drop semantics. But the backing implementation is still
`StaticProvider` — a `HashMap` seeded from config at startup. The credentials
are still plaintext, unbounded, and irrevocable.

This design replaces `StaticProvider` with a zerolease-backed provider in the
embedded (single-binary) deployment model.

## Scope

**In scope:**

- Session-scoped credential access initiated by trusted user messages
- Credential-injecting process supervisor for CLI tools and MCP servers
- In-process `Arc<Vault>` behind a crate feature gate (`embedded-vault`)
- Audit logging of all credential operations
- Lease-based lifecycle with automatic revocation

**Out of scope:**

- Cloud/VM deployment (separate design doc)
- Credential rotation or sync with upstream services (zerolease is not a
  secrets manager)
- Modifying third-party MCP servers or CLI tools
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
authorization for the *intended* code paths.

```
Trusted User ──message──▶ Orchestrator ──creates──▶ Session
                                                       │
                                                       ├──token──▶ Provisioner
                                                       │               │
                                                       │          vault.acquire()
                                                       │               │
                                                       │          scoped credentials
                                                       │
                                                       └──(future)──▶ Collaborators
```

**Trust chain:**

1. A **trusted user** sends an incoming message (Telegram, API, CLI prompt).
2. The orchestrator authenticates the user and creates a **session**.
3. The session produces a **session token** — a capability that authorizes
   credential requests scoped to this session's lifetime and purpose.
4. The provisioner (process supervisor) presents the session token when
   requesting credentials from the vault.
5. The vault grants credentials **scoped to the session**: bounded TTL,
   domain restrictions, use-count limits.
6. When the session ends (user disconnects, conversation completes, timeout),
   all leases issued under that session are revoked.

**Key properties:**

- **Human-initiated trust root.** Every credential access traces back to a
  specific user message. No standing privileges.
- **Session = blast radius.** In normal operation (no code-level compromise),
  credential access is limited to the scope of active sessions.
- **Extensible to collaboration.** A session token represents a trust context
  that could be shared when other humans join the work — the session is "this
  work context," not "this user's conversation."

### Trust Boundaries (Embedded)

| Component | Trust level | Enforcement |
|-----------|------------|-------------|
| The vault (in-process) | Fully trusted. Holds credentials, enforces policy. | N/A — the vault is the root of trust. |
| The orchestrator (zeroclaw) | **Effectively fully trusted** — shares address space with vault. Session scoping is defense-in-depth, not an enforced boundary. | Self-imposed: code discipline, session API. |
| CLI tools / MCP servers | Untrusted. Receive credentials via fd/env. Cannot outlive their supervisor. | Enforced: process isolation, process group kill, credential delivery mechanism. |
| The device (Pi / laptop) | Trusted platform. Physical access = game over. | Out of scope: full-disk encryption, physical security. |

**Relation to `docs/design.md`:** The original zerolease design doc marks
the orchestrator as "fully trusted." The embedded model is consistent with
this — the orchestrator and vault share an address space, so they share a
trust domain. Session scoping adds defense-in-depth (auditability, lifecycle
management, blast-radius reduction for bugs) but does not create a new trust
boundary. The cloud/VM model achieves actual trust separation.

## Architecture

### Component Ownership

| Component | Crate | Why |
|-----------|-------|-----|
| Process supervisor (`provision-run`) | `zerolease` | Natural extension of `zerolease-agent provision`. Manages child process lifecycle, env injection, lease revocation. |
| `ZeroleaseProvider` (trait impl) | `zerolease-provider` | Already exists. Implements `CredentialProvider` against a vault connection. |
| Session management | `zerolease` | Sessions are a vault-level concept — the vault issues and validates session tokens. |
| Tool registry wiring | `zeroclaw` | Connects `build_credential_provider()` to the vault. Feature-gated on `embedded-vault`. |
| MCP config integration | `zeroclaw` | Reads MCP server definitions, passes them to the process supervisor. |

### Feature Gate: `embedded-vault`

```toml
# zeroclaw/Cargo.toml
[features]
embedded-vault = ["zerolease/vault", "zerolease/sqlite-store", "zerolease/keychain"]
```

**With `embedded-vault`:**

- Zeroclaw constructs `Arc<Vault<KeychainSource, RusqliteStore, RusqliteAuditLog>>`
  at startup.
- `build_credential_provider()` returns a `ZeroleaseProvider` backed by this
  in-process vault.
- Single binary, no external services required. Suitable for Raspberry Pi,
  laptop, air-gapped environments.

**Without `embedded-vault`:**

- Zeroclaw depends only on `zerolease-types` (for `SecretName`, `LeaseGrant`,
  etc.) and `zerolease-provider`.
- `build_credential_provider()` connects to an external credential service
  (details in the cloud design doc).
- No vault code, no crypto dependencies compiled in.

### Process Supervisor

The process supervisor is the core mechanism. It handles both CLI tools and
MCP servers identically — the "swap-out game" pattern.

#### CLI Tool Flow

```
Session token ──▶ Supervisor
                      │
                 vault.request_lease("jira-pat", session_token)
                      │
                 lease granted (TTL=60s, domains=["*.atlassian.net"])
                      │
                 spawn child (in new process group):
                   fd 3 ← credential via pipe
                   exec: cred-shim → reads fd 3 → sets env → exec tool
                      │
                 child exits
                      │
                 killpg(child_pgid) — kill entire process group
                      │
                 vault.revoke_lease(lease_id)
                      │
                 audit: LeaseRevoked { tool: "gh", duration: 2.3s }
```

1. Tool execution request arrives (from agent conversation).
2. Supervisor presents session token, requests lease for required credentials.
3. Vault checks policy, grants lease with TTL and domain scope.
4. Supervisor spawns child process **in a new process group** (`setpgid(0, 0)`)
   with credentials delivered via the fd delivery mechanism (see below).
5. Child runs to completion (or is killed on lease expiry).
6. Supervisor kills **the entire process group** (`killpg`) — not just the
   direct child. This prevents grandchild processes from inheriting credentials
   and surviving revocation.
7. Supervisor revokes lease immediately after process group termination.
8. Audit event emitted with tool name, duration, and outcome.

#### Credential Delivery

**Default: fd-based delivery.** The supervisor creates an anonymous pipe (or
`memfd_create` on Linux), writes the credential, and passes the read end as
a file descriptor to the child process. A thin **credential shim** reads the
fd, sets the appropriate environment variable, closes the fd, then `exec`s
the actual tool binary.

This eliminates credential exposure through `/proc/<pid>/environ` (Linux)
and `proc_pidinfo` / `sysctl kern.procargs2` (macOS), which allow any
same-UID process to read another process's environment variables.

```
Supervisor
    │
    ├── pipe() → (read_fd, write_fd)
    ├── write(write_fd, credential)
    ├── close(write_fd)
    │
    └── spawn cred-shim:
            fd 3 = read_fd
            argv = ["cred-shim", "--env=JIRA_API_TOKEN", "--fd=3", "--", "jira-cli", "issue", "list"]
            │
            cred-shim:
              1. read(fd 3) → credential
              2. close(fd 3)
              3. setenv("JIRA_API_TOKEN", credential)
              4. exec("jira-cli", ["issue", "list"])
```

**Compatibility fallback: env var injection.** Some tools may not work with
the shim (e.g., tools that inspect their own process tree or argv). For
these, env var injection is available as an **explicit opt-in** per tool
definition, with a warning emitted in the audit log:

```toml
[[tool_credential_binding]]
tool = "legacy-cli"
secrets = ["legacy-key"]
delivery = "env"  # default is "fd"
# audit log will warn: "credential delivered via env var — /proc exposure risk"
```

#### MCP Server Flow

```
Session token ──▶ Supervisor
                      │
                 vault.request_lease("github-pat", session_token)
                      │
                 lease granted (TTL=300s, domains=["api.github.com"])
                      │
                 spawn child (in new process group):
                   fd 3 ← credential via pipe
                   exec: cred-shim → sets env → exec MCP server
                      │
                 MCP server handles batch of tool calls
                      │
                 batch complete OR lease approaching expiry
                      │
                 SIGTERM → graceful shutdown (5s) → killpg(SIGKILL)
                      │
                 vault.revoke_lease(lease_id)
```

MCP servers differ from CLI tools in one way: they are long-lived (relative
to a single tool call) but short-lived (relative to the session). The
supervisor:

1. Launches the MCP server in a **new process group** with credentials
   delivered via fd (same mechanism as CLI tools).
2. Proxies MCP protocol messages (stdio transport) between zeroclaw and
   the server.
3. Monitors lease TTL. On approaching expiry, either renews (subject to
   `max_renewals_per_lease`) or initiates graceful shutdown.
4. On batch completion (see definition below), tears down the server.
5. Kills the entire process group, then revokes the lease.

**MCP servers are NOT always-running.** They are started on-demand when
the agent needs a tool from that server, and torn down when the batch of
related tool calls completes. This is critical: an always-running MCP server
with injected credentials defeats the lease model.

#### Batch Definition

A **batch** ends when ALL of the following are true:

1. The orchestrator signals that it has no more pending tool calls for this
   MCP server.
2. An **idle timeout** (default: 10 seconds, configurable per-tool) has
   elapsed with no new tool calls arriving.
3. The lease has not expired.

If the lease expires before the batch completes, the supervisor initiates
graceful shutdown regardless. The idle timeout acts as a safety net — even
if the orchestrator fails to signal batch completion (e.g., due to a bug or
prompt injection manipulating the conversation flow), the server is torn down
after a bounded idle period.

The orchestrator's signal provides responsiveness (immediate teardown when
the agent is done with a tool). The idle timeout provides safety (bounded
credential lifetime regardless of orchestrator behavior).

### Session Lifecycle

```
┌──────────────────────────────────────────────────────┐
│                    SESSION                           │
│                                                      │
│  Created: trusted user sends message                 │
│  Token:   opaque, non-forgeable, bound to session ID │
│  Scope:   which credentials may be requested         │
│  TTL:     max session duration (configurable)        │
│                                                      │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐              │
│  │ Lease 1 │  │ Lease 2 │  │ Lease 3 │   ...        │
│  │ gh CLI  │  │ Jira MCP│  │ Notion  │              │
│  │ 60s TTL │  │ 300s TTL│  │ 60s TTL │              │
│  └─────────┘  └─────────┘  └─────────┘              │
│                                                      │
│  Ends: user disconnects / conversation done /        │
│        timeout / explicit revocation                 │
│                                                      │
│  On end: all child leases revoked, all child         │
│          processes terminated, audit summary emitted  │
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

# Tool-to-secret bindings: each tool can only access its bound secrets.
# The supervisor enforces this — a tool invocation for "jira-cli" can only
# request "jira-pat", never "github-pat", even within the same session.

[[tool_credential_binding]]
tool = "jira-cli"
secrets = ["jira-pat"]
domains = ["*.atlassian.net"]
env_var = "JIRA_API_TOKEN"

[[tool_credential_binding]]
tool = "gh"
secrets = ["github-pat"]
domains = ["api.github.com", "github.com"]
env_var = "GITHUB_TOKEN"

[[tool_credential_binding]]
tool = "npx @modelcontextprotocol/server-github"
secrets = ["github-pat"]
domains = ["api.github.com"]
env_var = "GITHUB_PERSONAL_ACCESS_TOKEN"

[[tool_credential_binding]]
tool = "notion-cli"
secrets = ["notion-key"]
domains = ["api.notion.com"]
env_var = "NOTION_API_KEY"
```

Tool-to-secret bindings prevent a confused-deputy attack: even if the
orchestrator (or a prompt injection) requests the wrong credential for a
tool, the policy engine rejects it. The supervisor MUST enforce that a tool
invocation can only request credentials that are bound to that tool in the
policy configuration.

## Security Considerations

### What Embedded Mode Provides

Embedded mode provides **lifecycle management, auditability, and
defense-in-depth** against accidental misuse and bugs. Specifically:

- **Credential lifecycle.** Leases expire; credentials delivered via fd are
  closed after exec; process groups are killed on revocation. No credential
  survives beyond its intended use in normal operation.
- **Lateral movement prevention.** Tool-to-secret bindings ensure a tool
  invoked for Jira cannot request the GitHub token, even within the same
  session.
- **Bounded access windows.** `max_session_duration` + `max_renewals_per_lease`
  \+ lease TTL = hard upper bound on credential accessibility.
- **Full audit trail.** Every lease acquisition, access, and revocation
  produces an audit event tied to session ID, user, tool, and timestamp.
- **Defense against prompt injection.** A prompt injection attack can only
  operate within the session's credential scope and tool-to-secret bindings.
  It cannot create new sessions (requires trusted user authentication),
  access credentials outside the session policy, or request credentials not
  bound to the tool being invoked.

### What Embedded Mode Does NOT Provide

- **Isolation from a compromised orchestrator.** The vault and orchestrator
  share an address space. Arbitrary code execution in the orchestrator =
  full vault access. This requires the VM deployment model.
- **Network-layer enforcement.** No proxy, no iptables, no egress filtering.
  A malicious tool can exfiltrate credentials through any network path during
  the lease window.
- **Protection against malicious use of allowed APIs.** A tool with a valid
  Jira lease can create/delete/modify Jira issues. Domain-scoping prevents
  *which* service, not *what actions*.
- **Supply chain protection.** The supervisor executes whatever binary is
  configured. A compromised npm package or typosquatted CLI tool gets
  credentials and network access. See mitigations below.
- **LLM context credential leakage prevention.** Tool output containing
  credential material (error messages, debug logs) may be fed back into
  the LLM context and subsequently exposed through conversation history.

### Concrete Attack Scenarios

These scenarios are documented for threat modeling. Each has a corresponding
mitigation (implemented or planned).

**Scenario 1: Prompt injection credential harvesting.**
A Jira issue body contains prompt injection text. The agent reads the issue
using its Jira credential. The injected prompt causes the agent to invoke a
shell tool that reads credentials from its environment and includes them in
tool output. The credential is now in the LLM context. The injected prompt
instructs the agent to exfiltrate via an HTTP call to an allowed domain.

*Mitigations:* Tool-to-secret binding (shell tool has no credential bindings).
Credential output redaction (scan tool output for known credential patterns
before feeding to LLM context — imperfect but raises the bar). Short lease
TTLs limit the window.

**Scenario 2: Malicious MCP server / CLI tool (supply chain).**
An attacker publishes a typosquatted package. The MCP server reads env vars,
posts credentials to an allowed domain as a GitHub Gist, then behaves
normally.

*Mitigations:* Executable allowlisting — the supervisor should only execute
binaries from a configured allowlist. Fd-based credential delivery (the
credential is on a pipe fd, not in env vars, so simple `env` commands don't
expose it — though a determined attacker can still `read(3, ...)`).
Audit log flags unrecognized executables.

**Scenario 3: Child process fork escape.**
A child process forks before being killed. The grandchild inherits all file
descriptors and env vars. SIGTERM kills the parent but not the grandchild.

*Mitigation:* Process group isolation (`setpgid` + `killpg`). On Linux,
consider a dedicated cgroup per tool invocation to prevent fork escape
entirely. The credential shim closes the fd before exec, so the grandchild
does not inherit the pipe — but env vars set by the shim persist in forked
children.

**Scenario 4: Session token theft via core dump.**
The orchestrator crashes; a core dump containing the session token in
cleartext is written to disk. Another process reads the dump and extracts
the token.

*Mitigation:* `prctl(PR_SET_DUMPABLE, 0)` (Linux) at startup when
`embedded-vault` is active. Disable crash reporting on macOS. Store session
tokens in `mlock`'d memory pages. Zeroize on session end.

**Scenario 5: Lease renewal as infinite access.**
A long conversation keeps renewing leases, providing continuous credential
access despite short TTLs.

*Mitigation:* `max_renewals_per_lease` (default: 3) and
`max_session_duration` (absolute hard cap). Renewal requires re-presenting
the session token. Optional: re-authentication for sessions exceeding a
configurable threshold (e.g., after 30 minutes, require user confirmation
via the originating channel).

### Mitigations Summary

| Mitigation | Status | Priority |
|-----------|--------|----------|
| Fd-based credential delivery (default) | Designed | P0 |
| Process group isolation (`setpgid` + `killpg`) | Designed | P0 |
| Tool-to-secret binding in policy | Designed | P1 |
| Hard-cap session/lease lifetimes | Designed | P1 |
| Fail closed on vault init failure | Designed | P1 |
| Audit log integrity (HMAC-signed entries) | Planned | P1 |
| Session token format (HMAC-SHA256, mlock'd, zeroized) | Planned | P2 |
| Executable allowlisting | Planned | P2 |
| Credential output redaction | Planned | P2 |
| Core dump prevention | Planned | P3 |
| Policy file integrity checking | Planned | P3 |
| Child process sandboxing (seccomp/sandbox-exec) | Future | P3 |

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

The session token is an HMAC-SHA256 over:

```
HMAC-SHA256(vault_session_key, session_id || created_at || expires_at || nonce)
```

- `vault_session_key`: derived from the vault's DEK, used only for session
  token signing. Compromising this key requires vault-level access.
- `nonce`: random 128-bit value, unique per session.
- The token is stored in `mlock`'d memory and zeroized when the session ends.
- Child processes never receive the session token — they receive credentials
  via fd, not the token itself.

In the embedded model, the HMAC key lives in the same process as the
orchestrator, so a memory disclosure vulnerability in any loaded library
compromises the signing key. This is an inherent limitation of the in-process
architecture (see "Honest Assessment" above).

### Audit Log Integrity

Audit entries are HMAC-signed with a key derived from the vault's DEK.
Each entry includes a hash of the previous entry, forming a hash chain.
Tampering with or deleting entries is detectable by verifying the chain.

For high-security embedded deployments, the audit log should be replicated
to a remote syslog or append-only storage before the local copy can be
tampered with. This is a deployment concern, not a code requirement.

The SQLite audit database uses WAL mode and restrictive filesystem
permissions (`0600`, owned by the zeroclaw process user).

### Open Questions (For Human Review)

1. **Credential output redaction.** Scanning tool output for credential
   patterns before feeding to the LLM is imperfect — credentials don't
   always have recognizable formats. Is this worth implementing, or is it
   security theater that provides false confidence?

2. **Re-authentication for long sessions.** Should sessions exceeding a
   threshold (e.g., 30 minutes) require re-authentication via the
   originating channel? This adds friction to long conversations but limits
   damage from prompt injection that keeps a session alive.

3. **Sandboxing child processes.** `seccomp-bpf` (Linux) or `sandbox-exec`
   (macOS, deprecated) can restrict child process syscalls. The
   implementation cost is significant and platform-specific. Is this worth
   the complexity for embedded deployments, or should we defer to the VM
   model for high-security use cases?

4. **Policy file integrity.** Should TOML policy files be signed or
   checksum-verified on load? On single-user embedded devices, a local
   attacker with filesystem write access could escalate their credential
   scope by modifying `allowed_secrets` or `max_ttl`. Physical access is
   already game over, so this may be low priority.

## Implementation Phases

### Phase 1: Session Infrastructure (zerolease)

- Add `Session` type: ID, user, channel, created_at, expires_at, policy
- Add `SessionToken` type: HMAC-SHA256 signed, bound to session ID + nonce
- Session token stored in `mlock`'d memory, zeroized on session end
- Add session creation/validation/revocation to vault API
- Add session policy configuration with `max_session_duration`,
  `max_renewals_per_lease`, `max_concurrent_leases`
- Add tool-to-secret binding schema and policy enforcement
- HMAC-signed audit log entries with hash chain
- Tests: session lifecycle, token validation, expiry, revocation,
  tool-to-secret binding enforcement, audit chain verification

### Phase 2: Process Supervisor (zerolease)

- `provision-run` command: takes session token + tool definition, manages
  child lifecycle
- Credential shim binary: reads credential from fd, sets env var, exec tool
- Fd-based credential delivery (anonymous pipe / `memfd_create`)
- Env var fallback with explicit opt-in and audit warning
- Process group isolation: `setpgid(0, 0)` on spawn, `killpg` on revocation
- Child process monitoring (exit, signals, timeout)
- Lease revocation on process group termination
- `prctl(PR_SET_DUMPABLE, 0)` on Linux when embedded-vault is active
- Fail-closed: supervisor refuses to run if vault is unavailable
  (no silent fallback to plaintext)
- Tests: CLI wrapping end-to-end, timeout behavior, signal handling,
  process group kill (verify grandchild processes are terminated),
  fd credential delivery, core dump prevention

### Phase 3: MCP Server Launching (zerolease)

- Extend supervisor for long-lived stdio-transport children
- MCP protocol proxying (stdin/stdout passthrough)
- Batch completion detection: orchestrator signal AND idle timeout (default
  10s) AND lease not expired — all three conditions required
- Graceful shutdown sequence (SIGTERM → 5s wait → killpg SIGKILL)
- Lease renewal subject to `max_renewals_per_lease`
- Executable allowlisting (optional, logged warning for unrecognized binaries)
- Tests: MCP server lifecycle, batch completion (all three conditions),
  lease renewal cap, idle timeout behavior

### Phase 4: Zeroclaw Integration

- Feature gate `embedded-vault` in `Cargo.toml`
- In-process vault construction at startup (keychain + sqlite)
- Wire `build_credential_provider()` to return vault-backed provider;
  return error (not `StaticProvider`) if vault init fails
- Session creation on incoming user message
- Tool registry integration: route tool calls through supervisor with
  tool-to-secret binding enforcement
- MCP config parsing: identify which MCP servers need credential injection
- Credential output redaction: scan tool output for known credential
  patterns before feeding to LLM context
- Tests: end-to-end with real vault, session-to-tool-call flow,
  fail-closed behavior, credential redaction

## Relation to Existing Code

| Existing code | Role in this design |
|--------------|-------------------|
| `CredentialProvider` trait (`zerolease-provider`) | Unchanged. Tools continue to call `acquire()`/`expose()`. |
| `StaticProvider` (`zerolease-provider`) | Remains when `embedded-vault` is off and no external service is configured. NOT used as silent fallback when vault init fails — fail-closed behavior requires explicit opt-in. |
| `build_credential_provider()` (zeroclaw `src/tools/mod.rs`) | Extended: when `embedded-vault` is on, constructs `ZeroleaseProvider` backed by in-process vault. Returns error on vault init failure. |
| `Vault<K, S, A>` (`zerolease`) | Used directly in-process. New: session-aware lease requests, HMAC-signed audit entries. |
| ADR-004 `ClientId` (zeroclaw) | Session ID composes with `ClientId` — a session is initiated by a client, and the client's identity is part of the session's trust root. |
| `SecurityPolicy` (zeroclaw) | Orthogonal. Security policy governs what the *agent* may do; session policy governs what *credentials* the agent may access via tool-to-secret bindings. |

## Values

In priority order, when design decisions conflict:

1. **Zero-trust by default.** Per-request credential resolution is ideal;
   per-session is the acceptable fallback. Never per-process or per-startup.
   Fail closed, never open.
2. **Honest about guarantees.** Embedded mode provides auditability and
   defense-in-depth. It does not provide credential isolation from a
   compromised orchestrator. Don't claim what you can't enforce.
3. **Transparent to existing tools.** CLI tools and MCP servers must work
   without modification. Credentials arrive via fd-to-env shim.
4. **Observable.** Every credential access produces a signed audit event.
   Silent failures are bugs. Audit integrity is verifiable.
5. **Incrementally adoptable.** One tool at a time. The feature gate means
   zero cost when not used.
6. **Simple over clever.** Flat policy files, fd injection, process group
   supervision. No custom protocol, no agent-side SDK, no tool modifications.
