# Design

zerolease is a credential vault for environments where AI coding agents need
access to secrets they shouldn't be trusted to hold. This document explains
the assumptions, threat model, and design decisions.

## Related Documents

- **[Credential Sidecar — Embedded Deployment](design-credential-sidecar-embedded.md)**:
  Design for session-scoped credential access in the embedded (single-binary)
  deployment model. Built-in tools use the `acquire()`/`expose()` closure
  pattern — credentials never escape closure scope. Sessions, tool-to-secret
  bindings, and audit provide defense-in-depth against bugs and prompt injection.
- **[Implementation Plan — Embedded](plans/embedded-credential-sidecar.md)**:
  Two-phase plan: session infrastructure in zerolease, then zeroclaw integration.
- A companion cloud/VM sidecar design doc is planned. It will cover the
  process supervisor, credential shim, fd-based delivery, and MCP server
  lifecycle management — all VM-mode concerns for securing external plugins
  inside QEMU guests.

## Two Deployment Models

zerolease supports two deployment models with fundamentally different trust
properties. This design document describes the shared core and the VM model.
The embedded model has its own design doc (linked above).

|                         | Embedded                               | VM (Cloud)                                           |
| ----------------------- | -------------------------------------- | ---------------------------------------------------- |
| **Vault location**      | In-process (`Arc<Vault>`)              | Separate host behind network boundary                |
| **Orchestrator trust**  | Same address space as vault            | Untrusted (requests credentials over TCP)            |
| **Tool execution**      | Built-in Rust (`expose()` closure)     | External processes (Claude Code + plugins)           |
| **Credential delivery** | Closure argument, zeroized on drop     | Fd shim / env var, process group isolation           |
| **Security model**      | Secure by construction (type system)   | Secure by enforcement (process + network)            |
| **Session tokens**      | Random opaque handle, `HashMap` lookup | HMAC-signed, stateless validation over network       |
| **Primary threat**      | Our own bugs, prompt injection         | Malicious/compromised tools, credential exfiltration |

The shared core — `Vault<K, S, A>`, leases, policy engine, audit log,
crypto, transports, types — serves both models. The enforcement layer
diverges: embedded mode needs no subprocess machinery; VM mode needs the
proxy, provisioner, supervisor, and iptables rules described below.

## The Problem

An AI coding agent that can run `git push`, call APIs, or deploy
infrastructure needs credentials. The conventional approach — put `GITHUB_TOKEN`
in the environment and let the agent use it — is dangerous:

- The agent (and every tool it invokes) has the raw credential for the entire session.
- The credential works against any domain, not just the one the agent needs.
- There's no way to revoke access without killing the process.
- There's no audit trail of what the credential was used for.
- A compromised or misbehaving tool can exfiltrate the credential.

zerolease replaces this with lease-based access: agents receive time-bounded,
domain-scoped handles to credentials. The credential material is managed by
the vault, not the agent.

## Threat Model

**What we defend against:**

- An agent tool that tries to use a credential against an unauthorized domain (e.g.,
  sending a GitHub token to `evil.com`).
- A tool that holds a credential in memory after the lease expires and tries to keep using it.
- A tool that reads credentials from the environment or filesystem and attempts to exfiltrate them via the network.
- Credential persistence after the agent's work is done.

**What we don't defend against:**

- A tool that exfiltrates data through an allowed domain (e.g., creating a GitHub gist
  with stolen data). Domain-level access control can't distinguish legitimate from
  malicious use of an allowed API.
- Side-channel attacks (timing, power analysis). This is a software vault, not an HSM.
- A compromised VM image. If the base image is tampered with, all bets are off.
- Denial of service by a tool that exhausts the proxy's resources. The proxy is hardened
  against common DoS vectors but is not a production-grade DDoS target.

**Trust boundaries (VM model):**

| Component                         | Trust level                                                                            |
| --------------------------------- | -------------------------------------------------------------------------------------- |
| The vault (host)                  | Fully trusted. Holds credentials, enforces policy.                                     |
| The orchestrator (Claw)           | Fully trusted. Manages VM lifecycle, issues tokens.                                    |
| The proxy (VM)                    | Trusted infrastructure. Runs as a separate user, enforces leases at the network layer. |
| The provisioner (VM)              | Trusted infrastructure. Runs once, handles the vault token, exits.                     |
| Claude Code (VM)                  | Untrusted. Receives credentials via env vars and config files.                         |
| Tools invoked by Claude Code (VM) | Untrusted. May attempt to exfiltrate credentials.                                      |

For embedded-mode trust boundaries, see the
[embedded design doc](design-credential-sidecar-embedded.md#trust-boundaries-embedded).

## Core Abstractions

### The Vault (`Vault<K, S, A>`)

The vault is generic over three pluggable backends:

- **`KeySource`** (`K`): Manages the data encryption key (DEK). Implementations: OS keychain, AWS KMS, environment variable.
- **`SecretStore`** (`S`): Persists encrypted secret blobs. Implementations: rusqlite, PostgreSQL, AWS Secrets Manager.
- **`AuditLog`** (`A`): Records every credential operation. Implementations: `TracingAuditLog` (emit to stdout/log aggregator), rusqlite, PostgreSQL.

These are chosen at compile time. A developer laptop uses `KeychainSource + RusqliteStore + RusqliteAuditLog`. A cloud deployment uses `KmsSource + AwsSecretsManagerStore + TracingAuditLog`.

### Leases

A lease is a time-bounded, domain-scoped handle to a credential. When an agent needs a GitHub token:

1. It requests a lease for `github-pat` scoped to `github.com`.
2. The vault checks the policy engine (deny-by-default, first-match grant list).
3. If allowed, the vault creates a `Lease` with a TTL, optional use count, and domain restrictions.
4. The agent receives a `LeaseGrant` (metadata: lease ID, expiry, domains) — not the credential itself.
5. To get the actual credential, the agent calls `access_secret(lease_id, target_domain)`.
6. The vault verifies the target domain is in the lease's allowed list, decrypts the secret, and
   returns it in a `LeaseGuard` that zeroizes on drop.

Leases expire automatically. They can be revoked at any time by the vault administrator or the orchestrator.

### Sessions

Sessions are a first-class vault concept that bind credential access to a
trust context — typically a user-initiated conversation or work unit.

A session has a token (opaque handle), a user identity, a policy (which
credentials may be requested, via tool-to-secret bindings), and lifetime
bounds (`max_session_duration`, `max_concurrent_leases`,
`max_renewals_per_lease`). Leases issued under a session are revoked when
the session ends.

Session implementation differs by deployment model:

- **Embedded:** Random 128-bit token, `HashMap` lookup in-process. The
  token never leaves the process. See the
  [embedded design doc](design-credential-sidecar-embedded.md).
- **VM:** Token format TBD (likely HMAC-signed for stateless validation
  across the network boundary). Defined in the VM design doc (planned).

### Transports

The vault speaks a JSON-over-length-prefixed-frames protocol. Three transports:

- **Unix domain socket**: For local processes. Identity from `SO_PEERCRED` (UID/PID).
- **TCP + token**: For QEMU VMs. Identity from a bearer token in the `ClientHello` handshake. Listener binds localhost only.
- **vsock**: For Firecracker VMs. Identity from the guest CID.

The transport provides a `PeerIdentity` (what the OS/network tells us about the peer). The `Authenticator` trait maps this to a `ConnectionIdentity` (role + agent binding). The vault dispatch logic enforces role-based access control.

### The Proxy (VM Model)

In VM deployments, credentials are injected into the environment where any process can read them.
Lease revocation is meaningless if the tool already has the raw token. The lease-aware proxy closes this gap:

- It runs as a long-lived process inside the VM, separate from the agent.
- All outgoing HTTPS traffic must pass through it (via `HTTPS_PROXY` env var + iptables fallback).
- On each connection attempt, it checks: does this domain have an active lease?
- If yes: TCP tunnel (no TLS termination, the proxy never sees credential material).
- If no: connection blocked.

When the orchestrator revokes the prompt-run token, the proxy starts blocking. The tool may have
the credential in memory, but it can't reach any server with it.

## Design Decisions

**Deny-by-default policy.** The policy engine uses a flat grant list, not a policy language like OPA or Cedar. First
match wins. If no rule matches, access is denied. This is intentionally simple — easy to audit, hard to misconfigure.

**Newtype IDs everywhere.** `SecretId`, `AgentId`, `LeaseId`, `SecretName`, `DomainScope` are all newtypes. You can't
accidentally pass an `AgentId` where a `SecretId` is expected. The compiler catches it.

**Zeroize on drop.** Secret values use `SecretString` and `Zeroize`. The `LeaseGuard` is not `Clone`, not `Serialize`,
and redacts in `Debug`. When the guard drops, the secret is overwritten in memory.

**Storage and audit are decoupled.** A `SecretStore` crate doesn't need to also provide an `AuditLog`. The AWS Secrets
Manager backend provides only `SecretStore`; you pair it with `TracingAuditLog` for audit. This lets you choose the
right tool for each job.

**The proxy doesn't terminate TLS** (VM model). It only needs the destination domain, which it gets from the HTTP
CONNECT request line (explicit proxy) or TLS SNI (transparent proxy). It never sees credential material inside the
encrypted tunnel. No custom CA cert, no per-API auth knowledge.

**The vault token dies with the provisioner** (VM model). The prompt-run token is used by the provisioner and never
written to the agent's environment. The provisioner exits, taking the token with it. If `credential-fill` (git
credential helper) needs vault access, it gets a separate, more restricted token.

**Default-deny outbound networking** (VM model). `iptables -P OUTPUT DROP` is applied at boot before any process start.
Only the proxy user can reach port 443. All other outbound traffic (UDP, ICMP, SSH, HTTP) is blocked. The VM is a
network jail with one exit.

**Embedded mode needs none of the above VM machinery.** All tools are
built-in Rust code using `acquire()`/`expose()`. Credentials never enter
environment variables, file descriptors, or child processes. There is no
proxy, no iptables, no provisioner. Session scoping and tool-to-secret
bindings provide the enforcement layer. See the
[embedded design doc](design-credential-sidecar-embedded.md).

## Encryption

Secrets are encrypted at rest using AEAD ciphers:

- **AES-256-GCM**: Hardware-accelerated on x86_64 via AES-NI. Default.
- **XChaCha20-Poly1305**: Constant-time, good for non-x86 targets or when you want a larger nonce.

The data encryption key (DEK) is managed by the `KeySource`. In KMS deployments, the DEK is itself encrypted by KMS
(envelope encryption) — the vault never makes a KMS call per secret operation, only on DEK load/rotate.

## What This Is Not

- **Not a secrets manager.** It doesn't generate, rotate, or sync credentials with upstream services. It stores
  credentials that an administrator puts in and controls how agents access them.
- **Not a network proxy for general use.** The proxy enforces lease state, not general access control. It's
  purpose-built for the VM deployment model.
- **Not an HSM.** Secrets exist as plaintext in the vault process's memory while being accessed. The vault is a software
  component, not a hardware security boundary.
