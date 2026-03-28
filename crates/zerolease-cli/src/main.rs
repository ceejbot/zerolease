//! zerolease-cli: credential wrapper for Claude Code in managed VMs.
//!
//! Acquires credentials from a zerolease vault via TCP + token auth
//! and makes them available to tools through native credential
//! mechanisms (env vars, config files, git credential helpers).
//!
//! # Subcommands
//!
//! - `exec`: Acquire credentials, inject into environment, exec a command
//! - `credential-fill`: Git credential helper protocol (called by git)

mod config_writer;
mod git_credential;
mod manifest;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing::level_filters::LevelFilter;
use zerolease::client::VaultClient;
use zerolease::transport::tcp::TcpConnector;

use crate::config_writer::{expand_template, expand_tilde, write_config};
use crate::manifest::{CredentialManifest, InjectMechanism};

/// Credential wrapper for Claude Code agents in managed VMs.
#[derive(Parser)]
#[command(
    name = "zerolease-cli",
    about = "Acquire credentials from a zerolease vault for AI agent tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Acquire credentials, inject into the environment, and exec a command.
    ///
    /// Reads a credential manifest describing which secrets to acquire
    /// and how to make them available (env vars, config files, git
    /// credential helper). Then execs the specified command with the
    /// credentials injected.
    Exec {
        /// Vault TCP address (host:port).
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
    },

    /// Git credential helper (called by git, not directly by users).
    ///
    /// Configure git to use this: `git config credential.helper '/path/to/zerolease-cli credential-fill'`
    ///
    /// Reads the vault address and token from ZEROLEASE_VAULT_ADDR and
    /// ZEROLEASE_TOKEN environment variables (set by `exec`).
    #[command(name = "credential-fill")]
    CredentialFill {
        /// The git credential operation: get, store, or erase.
        operation: String,

        /// Path to the credential manifest (for host→secret mapping).
        #[arg(long, default_value = "/etc/zerolease/credentials.json")]
        manifest: PathBuf,
    },
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
        Command::Exec {
            vault_addr,
            token,
            manifest,
            command,
        } => cmd_exec(vault_addr, &token, &manifest, &command).await,
        Command::CredentialFill {
            operation,
            manifest,
        } => cmd_credential_fill(&operation, &manifest).await,
    }
}

/// Execute the `exec` subcommand: acquire credentials and exec a command.
async fn cmd_exec(
    vault_addr: SocketAddr,
    token: &str,
    manifest_path: &Path,
    command: &[String],
) -> ExitCode {
    if command.is_empty() {
        eprintln!("error: no command specified");
        return ExitCode::from(2);
    }

    let manifest = match CredentialManifest::from_file(manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "error: failed to read manifest {}: {e}",
                manifest_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        vault = %vault_addr,
        credentials = manifest.credentials.len(),
        "connecting to vault"
    );

    let connector = TcpConnector::new(vault_addr, token);
    let mut client = match VaultClient::connect_with_token(&connector, connector.token()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: vault connection failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Collect env vars and config files to write.
    let mut env_vars: Vec<(String, String)> = Vec::new();

    for entry in &manifest.credentials {
        tracing::info!(
            secret = %entry.secret_name,
            domain = %entry.target_domain,
            "acquiring credential"
        );

        let grant = match client
            .request_lease("cli-wrapper", &entry.secret_name, &entry.target_domain)
            .await
        {
            Ok(g) => g,
            Err(e) => {
                eprintln!("error: lease failed for {}: {e}", entry.secret_name);
                return ExitCode::FAILURE;
            }
        };

        let secret_bytes = match client
            .access_secret(*grant.lease_id.as_uuid(), &entry.target_domain)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: access failed for {}: {e}", entry.secret_name);
                return ExitCode::FAILURE;
            }
        };

        let secret = match String::from_utf8(secret_bytes) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("error: secret {} is not valid UTF-8", entry.secret_name);
                return ExitCode::FAILURE;
            }
        };

        // Process each injection mechanism.
        for mechanism in &entry.inject {
            match mechanism {
                InjectMechanism::Env { var } => {
                    env_vars.push((var.clone(), secret.clone()));
                }
                InjectMechanism::File { path, template } => {
                    let expanded_path = expand_tilde(path);
                    let content = expand_template(template, &secret);
                    if let Err(e) = write_config(&expanded_path, &content) {
                        eprintln!(
                            "error: failed to write config {}: {e}",
                            expanded_path.display()
                        );
                        return ExitCode::FAILURE;
                    }
                    tracing::info!(path = %expanded_path.display(), "wrote config file");
                }
                InjectMechanism::GitCredential { .. } => {
                    // Handled by the credential-fill subcommand at git-request time.
                    // We just need to ensure the helper is configured.
                }
            }
        }

        tracing::info!(
            secret = %entry.secret_name,
            lease_id = %grant.lease_id.as_uuid(),
            "credential acquired"
        );
    }

    // Pass vault connection info through so credential-fill can reach the vault.
    env_vars.push(("ZEROLEASE_VAULT_ADDR".to_string(), vault_addr.to_string()));
    env_vars.push(("ZEROLEASE_TOKEN".to_string(), token.to_string()));

    // Configure git to use our credential helper.
    // The helper reads the manifest to map hosts → secrets.
    let self_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "zerolease-cli".to_string());
    let helper = format!(
        "{self_path} credential-fill --manifest {}",
        manifest_path.display()
    );
    env_vars.push(("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()));

    // Set credential helper via env — overrides any git config.
    env_vars.push((
        "GIT_CONFIG_COUNT".to_string(),
        "1".to_string(),
    ));
    env_vars.push((
        "GIT_CONFIG_KEY_0".to_string(),
        "credential.helper".to_string(),
    ));
    env_vars.push((
        "GIT_CONFIG_VALUE_0".to_string(),
        helper,
    ));

    let program = &command[0];
    let args = &command[1..];

    tracing::info!(program = %program, "exec");

    let err = exec_command(program, args, &env_vars);
    eprintln!("error: exec failed: {err}");
    ExitCode::FAILURE
}

/// Execute the `credential-fill` subcommand (git credential helper).
async fn cmd_credential_fill(operation: &str, manifest_path: &Path) -> ExitCode {
    // Only `get` does real work. `store` and `erase` are no-ops.
    if operation != "get" {
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

    // Read vault connection info from env (set by `exec`).
    let vault_addr: SocketAddr = match std::env::var("ZEROLEASE_VAULT_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(a) => a,
        None => {
            eprintln!("error: ZEROLEASE_VAULT_ADDR not set (run via `zerolease-cli exec`)");
            return ExitCode::FAILURE;
        }
    };

    let token = match std::env::var("ZEROLEASE_TOKEN") {
        Ok(t) => t,
        Err(_) => {
            eprintln!("error: ZEROLEASE_TOKEN not set (run via `zerolease-cli exec`)");
            return ExitCode::FAILURE;
        }
    };

    // Load manifest to get host→secret mapping.
    let manifest = match CredentialManifest::from_file(manifest_path) {
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
        Ok(false) => {
            // Host not in our map — let git try other helpers.
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: credential-fill failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Replace the current process with the given command.
fn exec_command(program: &str, args: &[String], env_vars: &[(String, String)]) -> io::Error {
    #[cfg(unix)]
    {
        use std::ffi::CString;

        // SAFETY: We are about to execvp, which replaces this process.
        // No other threads will observe these env changes.
        for (key, value) in env_vars {
            unsafe { std::env::set_var(key, value) };
        }

        let c_program = CString::new(program.as_bytes()).expect("program has null byte");
        let mut c_args: Vec<CString> = vec![c_program.clone()];
        for arg in args {
            c_args.push(CString::new(arg.as_bytes()).expect("arg has null byte"));
        }

        nix::unistd::execvp(&c_program, &c_args)
            .expect_err("execvp returned Ok")
            .into()
    }

    #[cfg(not(unix))]
    {
        match std::process::Command::new(program)
            .args(args)
            .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .status()
        {
            Ok(status) => io::Error::new(
                io::ErrorKind::Other,
                format!("child exited with {status}"),
            ),
            Err(e) => e,
        }
    }
}
