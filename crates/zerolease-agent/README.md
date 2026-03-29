# zerolease-cli

Credential wrapper for AI coding agents running inside managed VMs. Acquires secrets from a [zerolease](../../README.md) vault and makes them available to tools through their native credential mechanisms — environment variables, config files, and git credential helpers.

## How It Works

The CLI runs inside a QEMU VM that the orchestrator (the Claw) provisions for each prompt run. The VM image ships with **no credentials anywhere** — no `.netrc`, no SSH keys, no config files with tokens. `zerolease-cli` is the only path to a credential.

```
zerolease-cli exec --token $PROMPT_RUN_TOKEN \
  --manifest /etc/zerolease/credentials.json \
  -- claude code
```

1. Connects to the host-side vault over TCP using the prompt-run token
2. Reads the credential manifest to learn what secrets are needed
3. Acquires a lease for each secret (time-bounded, domain-scoped)
4. Injects each credential via the mechanisms specified in the manifest
5. Configures itself as the git credential helper
6. Execs `claude` (or whatever command follows `--`)
7. When the process exits, leases expire or the orchestrator revokes them

## The Credential Manifest

The manifest is a JSON file describing what to acquire and how to inject it. Each credential can use multiple injection mechanisms.

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
		}
	]
}
```

### Injection mechanisms

| Type             | What it does                              | Use when                         |
| ---------------- | ----------------------------------------- | -------------------------------- |
| `env`            | Sets an environment variable              | Tool reads a specific env var    |
| `file`           | Writes a config file from a template      | Tool reads a config file on disk |
| `git_credential` | Registers a git credential helper mapping | Tool is git (HTTPS)              |

For `file`, the template uses `${SECRET}` as the placeholder for the credential value. Files are written with mode 0600.

## Use Cases

### Git over HTTPS with a GitHub PAT

Git's credential helper protocol gives us **per-request domain validation** — the vault's core security property. When git needs to authenticate, it calls our credential helper with the target host. The helper acquires a lease scoped to exactly that domain.

```json
{
	"secret_name": "github-pat",
	"target_domain": "github.com",
	"inject": [{ "type": "git_credential", "host": "github.com" }]
}
```

The `exec` subcommand automatically configures `zerolease-cli credential-fill` as the git credential helper. When git runs `git push`, it asks the helper for credentials for `github.com`. The helper connects to the vault, leases the PAT for that domain, and returns it. Git uses it for that one operation. No token in the environment, no token on disk.

This is the most secure injection path. Use it for all git-over-HTTPS operations.

### Git over SSH

SSH key authentication goes through `ssh-agent`. A custom SSH agent that serves keys from the vault is planned but not yet implemented. In the meantime, you have two options:

**Option A: HTTPS instead of SSH.** Configure git to use HTTPS URLs with the credential helper. This is the recommended approach — it gives you per-request domain validation.

```bash
# In the VM image, force HTTPS for GitHub:
git config --system url."https://github.com/".insteadOf "git@github.com:"
```

Then use the `git_credential` mechanism as shown above.

**Option B: Inject an SSH key via a config file.** Store the private key as a vault secret and write it to disk at startup.

```json
{
	"secret_name": "deploy-ssh-key",
	"target_domain": "github.com",
	"inject": [{ "type": "file", "path": "~/.ssh/id_ed25519", "template": "${SECRET}" }]
}
```

This is less secure than the credential helper (the key exists on disk for the full session), but it works with unmodified SSH. The file is written mode 0600. You'll also want the VM image to have `~/.ssh/config` or `~/.ssh/known_hosts` pre-configured for the target hosts.

### GitHub CLI (`gh`)

The `gh` CLI reads the `GH_TOKEN` environment variable. Inject it alongside the git credential:

```json
{
	"secret_name": "github-pat",
	"target_domain": "github.com",
	"inject": [
		{ "type": "env", "var": "GH_TOKEN" },
		{ "type": "git_credential", "host": "github.com" }
	]
}
```

One vault secret, two injection mechanisms. `gh` gets the token via env var; `git` gets it via the credential helper with domain validation.

### Fastly CLI (`FASTLY_API_KEY`)

Any tool that reads a credential from an environment variable works the same way:

```json
{
	"secret_name": "fastly-api-key",
	"target_domain": "api.fastly.com",
	"inject": [{ "type": "env", "var": "FASTLY_API_KEY" }]
}
```

The `target_domain` is used for the vault's lease scoping. Even though the env var injection itself doesn't enforce domain restrictions, the vault's policy engine validates that this agent is authorized to access this secret for this domain.

Other examples of this pattern: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `DATADOG_API_KEY`, `SENTRY_DSN`, `SLACK_BOT_TOKEN`.

### AWS CLI with OIDC

AWS OIDC federation doesn't use a static secret — it exchanges a JWT for temporary credentials via `sts:AssumeRoleWithWebIdentity`. This is a different model than what zerolease manages (static secrets with lease wrapping).

**If your agent needs AWS access**, the recommended approach is to configure the QEMU VM's IAM role at the infrastructure level (instance profile or ECS task role), not through zerolease. The agent inherits the role's temporary credentials from the instance metadata service.

**If you must inject AWS credentials** (e.g., for cross-account access or a specific IAM user), you can store them as vault secrets:

```json
{
	"secret_name": "aws-cross-account-creds",
	"target_domain": "sts.amazonaws.com",
	"inject": [
		{ "type": "env", "var": "AWS_ACCESS_KEY_ID" },
		{ "type": "env", "var": "AWS_SECRET_ACCESS_KEY" }
	]
}
```

But note: the vault stores a single secret value per name. For AWS, you'd need to store the access key ID and secret key as separate vault secrets (one env var per secret), or store them as a JSON blob and use a file template:

```json
{
	"secret_name": "aws-cross-account",
	"target_domain": "sts.amazonaws.com",
	"inject": [
		{
			"type": "file",
			"path": "~/.aws/credentials",
			"template": "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = ${SECRET}"
		}
	]
}
```

In general, prefer infrastructure-level IAM over injecting AWS credentials.

### npm / private registries

npm reads authentication from `.npmrc` or the `NPM_TOKEN` environment variable:

```json
{
	"secret_name": "npm-token",
	"target_domain": "registry.npmjs.org",
	"inject": [
		{ "type": "env", "var": "NPM_TOKEN" },
		{ "type": "file", "path": "~/.npmrc", "template": "//registry.npmjs.org/:_authToken=${SECRET}" }
	]
}
```

For private registries, replace the registry URL:

```json
{
	"type": "file",
	"path": "~/.npmrc",
	"template": "//npm.pkg.github.com/:_authToken=${SECRET}\n@myorg:registry=https://npm.pkg.github.com"
}
```

### pip / PyPI

pip reads credentials from `~/.config/pip/pip.conf` or index URLs:

```json
{
	"secret_name": "pypi-token",
	"target_domain": "pypi.org",
	"inject": [
		{
			"type": "file",
			"path": "~/.config/pip/pip.conf",
			"template": "[global]\nextra-index-url = https://__token__:${SECRET}@pypi.org/simple/"
		}
	]
}
```

### Cargo / crates.io (or private registries)

Cargo reads registry tokens from `CARGO_REGISTRIES_<NAME>_TOKEN`:

```json
{
	"secret_name": "crates-io-token",
	"target_domain": "crates.io",
	"inject": [{ "type": "env", "var": "CARGO_REGISTRIES_CRATES_IO_TOKEN" }]
}
```

### Docker registry authentication

Docker reads credentials from `~/.docker/config.json`:

```json
{
	"secret_name": "docker-hub-token",
	"target_domain": "index.docker.io",
	"inject": [
		{
			"type": "file",
			"path": "~/.docker/config.json",
			"template": "{\"auths\":{\"https://index.docker.io/v1/\":{\"auth\":\"${SECRET}\"}}}"
		}
	]
}
```

The `${SECRET}` value should be the base64-encoded `username:password` string.

### Database connection strings

For tools that connect to databases via connection strings:

```json
{
	"secret_name": "postgres-url",
	"target_domain": "db.internal.example.com",
	"inject": [{ "type": "env", "var": "DATABASE_URL" }]
}
```

## Security Model

**No credentials exist until the wrapper acquires them.** The VM image has no secrets. Tools cannot fall back to a cached credential because there are none.

**The git credential helper validates domains per-request.** Every `git push`, `git pull`, or `git fetch` triggers a fresh lease for exactly the domain git is authenticating to. A compromised tool can't redirect the token to a different host.

**Environment variables are visible to child processes.** This is a known limitation of the `env` mechanism — any process running as the same user can read `/proc/<pid>/environ`. Mitigations: the VM is disposable (destroyed after the prompt run), leases have short TTLs, and the vault audit log records every access.

**Config files are mode 0600.** Only the owning user can read them. They exist on disk for the session duration.

**The prompt-run token is scoped.** Even if a tool reads `ZEROLEASE_TOKEN` from the environment, it can only acquire leases for the secrets listed in the manifest. The vault's policy engine enforces this.

## Subcommands

### `exec`

```
zerolease-cli exec [OPTIONS] --token <TOKEN> <COMMAND>...

Options:
  --vault-addr <HOST:PORT>   [default: 10.0.2.2:9100]
  --token <TOKEN>            Prompt-run auth token (or ZEROLEASE_TOKEN)
  --manifest <PATH>          Credential manifest [default: /etc/zerolease/credentials.json]
```

### `credential-fill`

Called by git, not by users directly. Configured automatically by `exec`.

```
zerolease-cli credential-fill <OPERATION> [--manifest <PATH>]
```

Operations: `get` (returns credential), `store` (no-op), `erase` (no-op).
