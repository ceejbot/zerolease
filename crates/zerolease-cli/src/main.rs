//! zerolease-cli: credential wrapper for Claude Code in managed VMs.
//!
//! Acquires credentials from a zerolease vault via TCP + token auth,
//! injects them into the environment, and execs `claude` with the
//! caller's arguments. All credentials are revoked on exit.
//!
//! # Usage
//!
//! ```text
//! zerolease-cli [OPTIONS] -- <claude args...>
//! ```
//!
//! Everything after `--` is passed through to `claude` unchanged.

mod manifest;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tracing::level_filters::LevelFilter;
use zerolease::client::VaultClient;
use zerolease::transport::tcp::TcpConnector;

use crate::manifest::CredentialManifest;

/// Credential wrapper for Claude Code agents in managed VMs.
///
/// Acquires credentials from a zerolease vault, sets them as
/// environment variables, and execs the specified command.
#[derive(Parser)]
#[command(
    name = "zerolease-cli",
    about = "Acquire credentials from a zerolease vault and exec a command",
    after_help = "Everything after -- is passed through to the command unchanged.\n\n\
                  Example:\n  zerolease-cli --token $TOKEN -- claude code"
)]
struct Cli {
    /// Vault TCP address (host:port).
    ///
    /// Default is QEMU user-mode networking gateway on port 9100.
    #[arg(long, default_value = "10.0.2.2:9100", env = "ZEROLEASE_VAULT_ADDR")]
    vault_addr: SocketAddr,

    /// Prompt-run authentication token.
    #[arg(long, env = "ZEROLEASE_TOKEN")]
    token: String,

    /// Path to the credential manifest JSON file.
    #[arg(long, default_value = "/etc/zerolease/credentials.json")]
    manifest: PathBuf,

    /// Command and arguments to exec (typically `claude`).
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize tracing (respects RUST_LOG env var).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::WARN.into())
                .from_env_lossy(),
        )
        .init();

    let cli = Cli::parse();

    if cli.command.is_empty() {
        eprintln!("error: no command specified after --");
        return ExitCode::from(2);
    }

    // Read the credential manifest.
    let manifest = match CredentialManifest::from_file(&cli.manifest) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: failed to read manifest {}: {e}", cli.manifest.display());
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        vault = %cli.vault_addr,
        credentials = manifest.credentials.len(),
        "connecting to vault"
    );

    // Connect to the vault.
    let connector = TcpConnector::new(cli.vault_addr, &cli.token);
    let mut client = match VaultClient::connect_with_token(&connector, connector.token()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: vault connection failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Acquire each credential and build the environment.
    let mut env_vars: Vec<(String, String)> = Vec::new();

    for entry in &manifest.credentials {
        tracing::info!(
            secret = %entry.secret_name,
            domain = %entry.target_domain,
            env_var = %entry.env_var,
            "acquiring credential"
        );

        // Request a lease.
        let grant = match client
            .request_lease(
                "cli-wrapper", // agent identity comes from the token's ConnectionIdentity
                &entry.secret_name,
                &entry.target_domain,
            )
            .await
        {
            Ok(g) => g,
            Err(e) => {
                eprintln!(
                    "error: failed to acquire lease for {}: {e}",
                    entry.secret_name
                );
                return ExitCode::FAILURE;
            }
        };

        // Access the secret value.
        let secret_bytes = match client
            .access_secret(*grant.lease_id.as_uuid(), &entry.target_domain)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "error: failed to access secret for {}: {e}",
                    entry.secret_name
                );
                return ExitCode::FAILURE;
            }
        };

        let secret_str = match String::from_utf8(secret_bytes) {
            Ok(s) => s,
            Err(_) => {
                eprintln!(
                    "error: secret {} is not valid UTF-8",
                    entry.secret_name
                );
                return ExitCode::FAILURE;
            }
        };

        env_vars.push((entry.env_var.clone(), secret_str));

        tracing::info!(
            secret = %entry.secret_name,
            lease_id = %grant.lease_id.as_uuid(),
            expires_at = %grant.expires_at,
            "credential acquired"
        );
    }

    // Build the command.
    let program = &cli.command[0];
    let args = &cli.command[1..];

    tracing::info!(program = %program, args = ?args, "exec");

    // Exec the command with credentials injected into the environment.
    // On Unix, this replaces the current process.
    let err = exec(program, args, &env_vars);
    eprintln!("error: exec failed: {err}");
    ExitCode::FAILURE
}

/// Replace the current process with the given command, injecting
/// additional environment variables. Returns the error if exec fails.
///
/// On Unix, this uses `execvp` which does not return on success.
/// On non-Unix, falls back to `std::process::Command`.
fn exec(program: &str, args: &[String], env_vars: &[(String, String)]) -> std::io::Error {
    #[cfg(unix)]
    {
        use std::ffi::CString;

        // Set environment variables before exec.
        // SAFETY: We are about to execvp, which replaces this process.
        // No other threads will observe these env changes.
        for (key, value) in env_vars {
            unsafe { std::env::set_var(key, value) };
        }

        // Build argv.
        let c_program = CString::new(program.as_bytes()).expect("program name has null byte");
        let mut c_args: Vec<CString> = vec![c_program.clone()];
        for arg in args {
            c_args.push(CString::new(arg.as_bytes()).expect("arg has null byte"));
        }

        // execvp replaces this process — does not return on success.
        nix::unistd::execvp(&c_program, &c_args)
            .expect_err("execvp returned Ok, which should be impossible")
            .into()
    }

    #[cfg(not(unix))]
    {
        // Fallback for non-Unix: spawn a child process.
        match std::process::Command::new(program)
            .args(args)
            .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .status()
        {
            Ok(status) => std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("child exited with {status}"),
            ),
            Err(e) => e,
        }
    }
}
