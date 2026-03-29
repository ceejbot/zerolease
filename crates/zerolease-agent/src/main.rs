//! zerolease-agent: VM-side agent for credential provisioning and
//! lease-aware network enforcement.
//!
//! Three subcommands:
//!
//! - `provision`: Acquire credentials from the vault, write env vars and config
//!   files, write lease state for the proxy, exit.
//! - `proxy`: Lease-aware HTTPS CONNECT proxy that blocks traffic when leases
//!   expire or are revoked.
//! - `credential-fill`: Git credential helper protocol.

mod config_writer;
mod git_credential;
pub mod lease_state;
mod manifest;
mod provision;
mod proxy;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing::level_filters::LevelFilter;

/// VM-side agent for zerolease credential management.
#[derive(Parser)]
#[command(
    name = "zerolease-agent",
    about = "Credential provisioner, lease-aware proxy, and git credential helper"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Acquire credentials from the vault and write them to the environment.
    ///
    /// Reads a credential manifest, acquires leases for each credential,
    /// writes env vars to a sourceable file, config files to disk, and
    /// a lease state file for the proxy. Then exits.
    Provision(provision::ProvisionArgs),

    /// Run the lease-aware HTTPS proxy.
    ///
    /// Blocks outgoing HTTPS connections to domains without active leases.
    /// Reads lease state from a file written by the provisioner.
    Proxy(proxy::ProxyArgs),

    /// Git credential helper (called by git, not directly by users).
    ///
    /// Reads vault connection info from ZEROLEASE_VAULT_ADDR and
    /// ZEROLEASE_CREDENTIAL_TOKEN environment variables.
    #[command(name = "credential-fill")]
    CredentialFill(CredentialFillArgs),
}

#[derive(clap::Args)]
struct CredentialFillArgs {
    /// The git credential operation: get, store, or erase.
    operation: String,

    /// Path to the credential manifest (for host→secret mapping).
    #[arg(long, default_value = "/etc/zerolease/credentials.json")]
    manifest: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::WARN.into())
                .from_env_lossy(),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Provision(args) => provision::run(args).await,
        Command::Proxy(args) => proxy::run(args).await,
        Command::CredentialFill(args) => cmd_credential_fill(args).await,
    }
}

/// Execute the `credential-fill` subcommand (git credential helper).
async fn cmd_credential_fill(args: CredentialFillArgs) -> ExitCode {
    use std::collections::HashMap;
    use std::io;

    if args.operation != "get" {
        return ExitCode::SUCCESS;
    }

    let mut stdin = io::BufReader::new(io::stdin());
    let request = match git_credential::CredentialRequest::parse(&mut stdin) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to parse git credential request: {e}");
            return ExitCode::FAILURE;
        }
    };

    let vault_addr: std::net::SocketAddr = match std::env::var("ZEROLEASE_VAULT_ADDR").ok().and_then(|s| s.parse().ok())
    {
        Some(a) => a,
        None => {
            eprintln!("error: ZEROLEASE_VAULT_ADDR not set");
            return ExitCode::FAILURE;
        }
    };

    // credential-fill gets its own restricted token, not the prompt-run token.
    let token = match std::env::var("ZEROLEASE_CREDENTIAL_TOKEN") {
        Ok(t) => t,
        Err(_) => {
            eprintln!("error: ZEROLEASE_CREDENTIAL_TOKEN not set");
            return ExitCode::FAILURE;
        }
    };

    let manifest = match manifest::CredentialManifest::from_file(&args.manifest) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: failed to read manifest: {e}");
            return ExitCode::FAILURE;
        }
    };

    let host_map: HashMap<String, (String, String)> = manifest
        .git_host_map()
        .into_iter()
        .map(|(k, (s, d))| (k, (s.to_string(), d.to_string())))
        .collect();

    match git_credential::handle_get(&request, &host_map, vault_addr, &token).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: credential-fill failed: {e}");
            ExitCode::FAILURE
        }
    }
}
