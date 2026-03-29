//! Credential provisioner: acquires leases from the vault, writes
//! credentials to env files and config files, writes lease state
//! for the proxy, then exits.
//!
//! The provisioner runs once at VM boot. It does NOT wrap or exec
//! any process — it provisions and exits. The vault token dies with
//! this process and never enters the agent's environment.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use uuid::Uuid;
use zerolease::audit::RevocationReason;
use zerolease::client::VaultClient;
use zerolease::transport::tcp::TcpConnector;

use crate::config_writer::{expand_template, expand_tilde, write_config};
use crate::lease_state::{LeaseInfo, LeaseState};
use crate::manifest::{CredentialManifest, InjectMechanism};

#[derive(clap::Args)]
pub struct ProvisionArgs {
    /// Vault TCP address (host:port).
    #[arg(long, default_value = "10.0.2.2:9100", env = "ZEROLEASE_VAULT_ADDR")]
    vault_addr: SocketAddr,

    /// Prompt-run authentication token. Used only by this process;
    /// never written to the env file.
    #[arg(long, env = "ZEROLEASE_TOKEN")]
    token: String,

    /// Path to the credential manifest JSON file.
    #[arg(long, default_value = "/etc/zerolease/credentials.json")]
    manifest: PathBuf,

    /// Path to write the sourceable env file.
    #[arg(long, default_value = "/etc/zerolease/env")]
    env_file: PathBuf,

    /// Path to write the lease state file (for the proxy).
    #[arg(long, default_value = "/var/run/zerolease/leases.json")]
    lease_file: PathBuf,

    /// Optional: token for the git credential helper (scoped more
    /// narrowly than the prompt-run token). Written to the env file
    /// as ZEROLEASE_CREDENTIAL_TOKEN.
    #[arg(long)]
    credential_token: Option<String>,
}

pub async fn run(args: ProvisionArgs) -> ExitCode {
    let manifest = match CredentialManifest::from_file(&args.manifest) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: failed to read manifest {}: {e}", args.manifest.display());
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        vault = %args.vault_addr,
        credentials = manifest.credentials.len(),
        "connecting to vault"
    );

    let connector = TcpConnector::new(args.vault_addr, &args.token);
    let mut client = match VaultClient::connect_with_token(&connector, connector.token()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: vault connection failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut env_lines = String::new();
    let mut lease_state = LeaseState::new();
    // Track acquired leases so we can revoke them if provisioning fails partway.
    let mut acquired_leases: Vec<Uuid> = Vec::new();

    let result = acquire_credentials(
        &mut client, &manifest, &mut env_lines, &mut lease_state, &mut acquired_leases,
    )
    .await;

    if let Err(msg) = result {
        eprintln!("error: {msg}");
        // Rollback: revoke all acquired leases before exiting.
        if !acquired_leases.is_empty() {
            eprintln!("rolling back {} acquired lease(s)...", acquired_leases.len());
            for lease_id in &acquired_leases {
                if let Err(e) = client.revoke_lease(*lease_id, RevocationReason::AdminRevoked).await {
                    tracing::warn!(%lease_id, error = %e, "failed to revoke during rollback");
                }
            }
        }
        return ExitCode::FAILURE;
    }

    // Add vault address for credential-fill (but NOT the prompt-run token).
    writeln!(env_lines, "export ZEROLEASE_VAULT_ADDR='{}'", args.vault_addr).expect("string write infallible");

    if let Some(ref cred_token) = args.credential_token {
        writeln!(
            env_lines,
            "export ZEROLEASE_CREDENTIAL_TOKEN='{}'",
            cred_token.replace('\'', "'\\''")
        )
        .expect("string write infallible");
    }

    // Configure git credential helper.
    let self_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "zerolease-agent".to_string());
    writeln!(env_lines, "export GIT_TERMINAL_PROMPT=0").expect("string write infallible");
    writeln!(env_lines, "export GIT_CONFIG_COUNT=1").expect("string write infallible");
    writeln!(env_lines, "export GIT_CONFIG_KEY_0='credential.helper'").expect("string write infallible");
    writeln!(
        env_lines,
        "export GIT_CONFIG_VALUE_0='{self_path} credential-fill --manifest {}'",
        args.manifest.display()
    )
    .expect("string write infallible");

    // Set HTTPS proxy.
    writeln!(env_lines, "export HTTPS_PROXY='http://127.0.0.1:8080'").expect("string write infallible");
    writeln!(env_lines, "export HTTP_PROXY='http://127.0.0.1:8080'").expect("string write infallible");

    // Write env file.
    if let Err(e) = write_env_file(&args.env_file, &env_lines) {
        eprintln!("error: failed to write env file: {e}");
        return ExitCode::FAILURE;
    }
    tracing::info!(path = %args.env_file.display(), "wrote env file");

    // Write lease state for the proxy.
    if let Err(e) = lease_state.write_atomic(&args.lease_file) {
        eprintln!("error: failed to write lease state: {e}");
        return ExitCode::FAILURE;
    }
    tracing::info!(
        path = %args.lease_file.display(),
        domains = lease_state.leases.len(),
        "wrote lease state"
    );

    ExitCode::SUCCESS
}

/// Acquire all credentials from the vault, populating env_lines, lease_state,
/// and acquired_leases. Returns Err(message) on the first failure.
async fn acquire_credentials(
    client: &mut VaultClient<TcpConnector>,
    manifest: &CredentialManifest,
    env_lines: &mut String,
    lease_state: &mut LeaseState,
    acquired_leases: &mut Vec<Uuid>,
) -> std::result::Result<(), String> {
    for entry in &manifest.credentials {
        tracing::info!(secret = %entry.secret_name, domain = %entry.target_domain, "acquiring");

        let grant = client
            .request_lease("provisioner", &entry.secret_name, &entry.target_domain)
            .await
            .map_err(|e| format!("lease failed for {}: {e}", entry.secret_name))?;

        acquired_leases.push(*grant.lease_id.as_uuid());

        let secret_bytes = client
            .access_secret(*grant.lease_id.as_uuid(), &entry.target_domain)
            .await
            .map_err(|e| format!("access failed for {}: {e}", entry.secret_name))?;

        let secret =
            String::from_utf8(secret_bytes).map_err(|_| format!("secret {} is not valid UTF-8", entry.secret_name))?;

        lease_state.leases.insert(
            entry.target_domain.clone(),
            LeaseInfo {
                lease_id: grant.lease_id.as_uuid().to_string(),
                expires_at: grant.expires_at,
            },
        );

        for mechanism in &entry.inject {
            match mechanism {
                InjectMechanism::Env { var } => {
                    writeln!(env_lines, "export {var}='{}'", secret.replace('\'', "'\\''"))
                        .expect("string write infallible");
                }
                InjectMechanism::File { path, template } => {
                    let expanded = expand_tilde(path);
                    let content = expand_template(template, &secret);
                    write_config(&expanded, &content)
                        .map_err(|e| format!("failed to write {}: {e}", expanded.display()))?;
                    tracing::info!(path = %expanded.display(), "wrote config file");
                }
                InjectMechanism::GitCredential { .. } => {}
            }
        }

        tracing::info!(
            secret = %entry.secret_name,
            lease_id = %grant.lease_id.as_uuid(),
            "provisioned"
        );
    }

    Ok(())
}

/// Write the env file with mode 0600.
fn write_env_file(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}
