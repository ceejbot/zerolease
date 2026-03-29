# Guide: VM Deployment with the Lease-Aware Proxy

This guide describes the full production deployment model: AI coding agents running inside disposable QEMU virtual machines, managed by an orchestrator (the Claw), with the lease-aware proxy enforcing credential lifecycle at the network layer.

This is the most secure deployment model zerolease supports. It combines defense-in-depth across four layers: vault policy, lease TTLs, network enforcement, and VM disposal.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  AWS Instance                                                    │
│                                                                  │
│  ┌─────────────────────────────────────────┐                     │
│  │  The Claw (orchestrator)                │                     │
│  │                                         │                     │
│  │  ┌──────────────┐  ┌─────────────────┐  │                     │
│  │  │  zerolease   │  │  Token Manager  │  │                     │
│  │  │  vault       │  │                 │  │                     │
│  │  │  TCP :9100   │  │  Creates tokens │  │                     │
│  │  │  (localhost) │  │  per prompt run │  │                     │
│  │  └──────┬───────┘  └────────┬────────┘  │                     │
│  └─────────┼───────────────────┼───────────┘                     │
│            │                   │                                  │
│     ┌──────┴───────────────────┴──────────────────────┐          │
│     │  QEMU host-forwarded port 9100                  │          │
│     └──────┬────────────────┬────────────────┬────────┘          │
│            │                │                │                    │
│  ┌─────────┴──────┐ ┌──────┴───────┐ ┌──────┴───────┐           │
│  │  QEMU VM       │ │  QEMU VM     │ │  QEMU VM     │           │
│  │  prompt-run-001│ │  prompt-run-  │ │  prompt-run-  │           │
│  │                │ │  002         │ │  003         │           │
│  │  ┌───────────┐ │ │              │ │              │           │
│  │  │ proxy     │ │ │    ...       │ │    ...       │           │
│  │  │ :8080     │ │ │              │ │              │           │
│  │  │ :8443     │ │ │              │ │              │           │
│  │  ├───────────┤ │ │              │ │              │           │
│  │  │ Claude    │ │ │              │ │              │           │
│  │  │ Code      │ │ │              │ │              │           │
│  │  │ + tools   │ │ │              │ │              │           │
│  │  └───────────┘ │ │              │ │              │           │
│  │  postgres, etc │ │              │ │              │           │
│  └────────────────┘ └──────────────┘ └──────────────┘           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## The VM Image

The VM image is pre-baked with the development environment and the zerolease agent binary. It ships with **no credentials of any kind**:

- No `~/.ssh/id_*`
- No `~/.netrc`
- No `~/.npmrc` with tokens
- No `~/.config/gh/hosts.yml`
- No environment variables with secrets

This is not incidental — it's a security requirement. zerolease-agent is the **sole credential source** inside the VM. Tools cannot fall back to a cached credential because there are none.

### What the image includes

- `zerolease-agent` binary (the `provision`, `proxy`, and `credential-fill` subcommands)
- Git configured to use the credential helper: `git config --system credential.helper '/usr/bin/zerolease-agent credential-fill'`
- Git configured to prefer HTTPS over SSH: `git config --system url."https://github.com/".insteadOf "git@github.com:"`
- iptables rules applied at init (see below)
- IPv6 disabled: `sysctl net.ipv6.conf.all.disable_ipv6=1`
- Language runtimes, databases, and other tools the agents need

### iptables rules (applied at init, before any network-capable process)

```bash
# Default deny all outbound.
iptables -P OUTPUT DROP

# Allow loopback (proxy ↔ agent communication).
iptables -A OUTPUT -o lo -j ACCEPT

# Allow the proxy user to reach external port 443.
iptables -A OUTPUT -m owner --uid-owner proxy-user -p tcp --dport 443 -j ACCEPT

# Allow DNS to local resolver only.
iptables -A OUTPUT -d 127.0.0.1 -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 53 -j ACCEPT

# Allow the provisioner to reach the host vault.
iptables -A OUTPUT -d 10.0.2.2 -p tcp --dport 9100 \
  -m owner --uid-owner provision-user -j ACCEPT

# Transparent proxy fallback: redirect any port-443 traffic that
# bypasses HTTPS_PROXY to the transparent proxy.
iptables -t nat -A OUTPUT -p tcp --dport 443 \
  -m owner ! --uid-owner proxy-user \
  -j REDIRECT --to-port 8443
```

This creates a network jail. The only outbound path is through the proxy, which checks lease state on every connection. DNS is local-only. UDP, ICMP, SSH, and HTTP (port 80) are blocked.

## VM Lifecycle

### Phase 1: Boot

The Claw boots the QEMU VM. The VM starts with iptables rules in place but no credentials, no tokens, and no network access (everything is blocked by default-deny).

### Phase 2: Proxy startup

```bash
zerolease-agent proxy \
  --port 8080 \
  --transparent-port 8443 \
  --lease-file /var/run/zerolease/leases.json &
```

The proxy starts in deny-all mode (no leases loaded yet). Any outgoing connection is blocked. This is intentional — the proxy must be running before any credentials exist in the VM.

### Phase 3: Provisioning

The Claw sends the prompt-run token to the VM and triggers provisioning:

```bash
zerolease-agent provision \
  --vault-addr 10.0.2.2:9100 \
  --token "$PROMPT_RUN_TOKEN" \
  --manifest /etc/zerolease/credentials.json \
  --env-file /etc/zerolease/env \
  --lease-file /var/run/zerolease/leases.json \
  --credential-token "$CREDENTIAL_HELPER_TOKEN"
```

The provisioner:
1. Connects to the host vault with the prompt-run token.
2. Acquires a lease for each credential in the manifest.
3. Writes credential values to `/etc/zerolease/env` (sourceable shell file, mode 0600).
4. Writes config files (`.npmrc`, `pip.conf`, etc.) per the manifest.
5. Writes the lease state file (`/var/run/zerolease/leases.json`) — the proxy picks this up and starts allowing connections to leased domains.
6. Writes `ZEROLEASE_CREDENTIAL_TOKEN` (a separate, restricted token for the git credential helper) to the env file.
7. Exits. The prompt-run token dies with this process.

After provisioning:
- The env file contains credential values and configuration (`HTTPS_PROXY`, `GIT_CONFIG_*`, `ZEROLEASE_VAULT_ADDR`, `ZEROLEASE_CREDENTIAL_TOKEN`).
- The proxy has lease state and is now allowing connections to leased domains.
- The prompt-run token no longer exists in any process or file.

### Phase 4: Agent execution

```bash
source /etc/zerolease/env
claude code
```

Claude Code starts with credentials in its environment. When it runs `git push`:

1. Git calls `zerolease-agent credential-fill get` with the target host.
2. The credential helper connects to the vault with the restricted `ZEROLEASE_CREDENTIAL_TOKEN`, acquires a lease scoped to that exact domain, and returns the credential.
3. Git makes the HTTPS request through the proxy (`HTTPS_PROXY=http://127.0.0.1:8080`).
4. The proxy checks: does `github.com` have an active lease? Yes → tunnel established.
5. The git operation completes.

When Claude Code runs `curl https://api.fastly.com/...` with `FASTLY_API_KEY` in the env:
1. curl connects through the proxy.
2. The proxy checks: does `api.fastly.com` have an active lease? Yes → tunnel established.
3. The request completes.

When a tool tries to reach `https://evil.com`:
1. The proxy checks: does `evil.com` have an active lease? No → connection blocked (403).

### Phase 5: Completion or revocation

The prompt run completes (or the Claw decides to stop it):

1. The Claw revokes the prompt-run token in the vault.
2. All leases issued under that token expire immediately.
3. The proxy's background refresh detects the expired leases and starts blocking.
4. The Claw destroys the VM.

If the Claw crashes before revoking, the leases still expire on their own (TTL-based). The VM continues to function until the leases expire, then all network access is blocked. The VM can be cleaned up later.

## The Credential Manifest

The manifest describes what the agent needs. It's injected into the VM alongside the provisioner configuration (via cloud-init, QEMU `-fw_cfg`, or a shared filesystem).

```json
{
  "credentials": [
    {
      "secret_name": "github-pat",
      "target_domain": "github.com",
      "inject": [
        { "type": "env", "var": "GH_TOKEN" },
        { "type": "git_credential", "host": "github.com" }
      ]
    },
    {
      "secret_name": "npm-token",
      "target_domain": "registry.npmjs.org",
      "inject": [
        { "type": "env", "var": "NPM_TOKEN" },
        {
          "type": "file",
          "path": "~/.npmrc",
          "template": "//registry.npmjs.org/:_authToken=${SECRET}"
        }
      ]
    },
    {
      "secret_name": "fastly-key",
      "target_domain": "api.fastly.com",
      "inject": [
        { "type": "env", "var": "FASTLY_API_KEY" }
      ]
    }
  ]
}
```

Each credential can use multiple injection mechanisms:

| Mechanism | How it works | Security properties |
|-----------|-------------|---------------------|
| `env` | Sets an environment variable | Visible to all child processes. Proxy enforces at the network level. |
| `file` | Writes a config file from a template (`${SECRET}` placeholder, mode 0600) | Only readable by the owning user. Proxy enforces at the network level. |
| `git_credential` | Registers a git credential helper mapping for this host | Per-request domain validation via the vault. The strongest injection mechanism. |

## Security Properties

**Four layers of defense:**

1. **Vault policy**: The policy engine decides which agents can access which secrets for which domains. Deny-by-default.
2. **Lease TTLs**: Every credential access is time-bounded. Leases expire automatically.
3. **Network enforcement**: The proxy blocks connections to domains without active leases. Lease revocation means network cutoff.
4. **VM disposal**: The VM is destroyed when the prompt run ends. No credential material persists.

**Assumptions that must hold:**

- The VM image is trusted and not tampered with. (Consider dm-verity or signed images.)
- The proxy runs as a separate user that the agent cannot kill, signal, or impersonate.
- iptables rules are applied before any network-capable process starts.
- IPv6 is disabled (or duplicated in ip6tables).
- The prompt-run token is not baked into the VM image — it's delivered at provisioning time and dies with the provisioner process.

**Known residual risks:**

- A tool with a lease for `github.com` can exfiltrate data through legitimate GitHub API calls. Domain-level access control cannot prevent this.
- Environment variables are readable by sibling processes (`/proc/<pid>/environ`). Mitigated by VM disposal and lease TTLs.
- The proxy's transparent mode (SNI extraction) is weaker than the explicit mode (CONNECT). SNI can be spoofed. The transparent mode is defense-in-depth, not primary enforcement.

## Proxy Hardening

The proxy validates more than just lease state:

- **Port restriction**: Only ports 443 and 8443 are allowed. A `CONNECT github.com:22` is blocked even with a valid domain lease.
- **Private IP blocking**: DNS resolution results are checked against private ranges (10.x, 172.16.x, 192.168.x, 169.254.x). Prevents SSRF to cloud metadata services or internal networks.
- **Hostname validation**: Only valid DNS characters allowed. Path traversal and injection attempts are rejected.
- **Request size limits**: CONNECT request lines capped at 8 KiB, max 64 headers. Prevents OOM via unbounded reads.
- **Tunnel timeout**: Tunnels are forcibly closed when the lease expires (or after 1 hour, whichever comes first).
- **Case normalization**: Domain matching is case-insensitive.
- **Absent SNI = deny**: The transparent proxy drops connections without a parseable SNI hostname.

## What the Claw Provides

zerolease provides the vault, transports, and agent binary. The orchestrator (the Claw) is responsible for:

| Responsibility | What it means |
|---------------|---------------|
| **Token lifecycle** | Create a prompt-run token before booting the VM. Revoke it when done. |
| **Manifest generation** | Decide which credentials this prompt run needs, based on the repos and tools involved. |
| **VM provisioning** | Boot QEMU with the right image, host-forward port 9100, inject the manifest and token. |
| **VM destruction** | Kill the VM when the prompt run ends (or on timeout). |
| **Policy management** | Configure the vault's grant list: which agents get which secrets for which domains. |
| **Authenticator implementation** | Map prompt-run tokens to `ConnectionIdentity` (role, agent binding). The `TokenAuthenticator` in zerolease is a reference implementation; production deployments may need richer logic. |
| **Monitoring** | Watch audit events, set alerts for anomalies (unexpected domains, high lease counts, revocation failures). |
