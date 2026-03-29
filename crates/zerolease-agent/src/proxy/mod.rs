//! Lease-aware HTTPS proxy.
//!
//! Two modes:
//! - **Explicit proxy** (default port 8080): Handles HTTP CONNECT
//!   requests. Tools reach it via `HTTPS_PROXY` env var.
//! - **Transparent proxy** (default port 8443): Handles iptables-
//!   redirected TLS connections, extracts domain from TLS SNI.
//!   Defense-in-depth only — deny when SNI is absent.
//!
//! Both modes check the lease state before allowing a connection.
//! If the domain has no active lease, the connection is blocked.

mod connect;
mod sni;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::lease_state::LeaseState;

/// Shared proxy state, protected by a read-write lock so the
/// background refresh task can update while handlers read.
pub type SharedLeaseState = Arc<RwLock<LeaseState>>;

#[derive(clap::Args)]
pub struct ProxyArgs {
    /// Port for the explicit HTTPS CONNECT proxy.
    #[arg(long, default_value = "8080")]
    pub port: u16,

    /// Port for the transparent proxy (iptables-redirected TLS).
    #[arg(long, default_value = "8443")]
    pub transparent_port: u16,

    /// Path to the lease state file (written by the provisioner).
    #[arg(long, default_value = "/var/run/zerolease/leases.json")]
    pub lease_file: PathBuf,

    /// How often to reload the lease state file (seconds).
    #[arg(long, default_value = "5")]
    pub refresh_interval: u64,
}

pub async fn run(args: ProxyArgs) -> ExitCode {
    // Load initial lease state (may not exist yet if provisioner hasn't run).
    let initial_state = LeaseState::read_from(&args.lease_file).unwrap_or_default();
    let state: SharedLeaseState = Arc::new(RwLock::new(initial_state));

    // Spawn background task to reload lease state periodically.
    let refresh_state = Arc::clone(&state);
    let refresh_path = args.lease_file.clone();
    let refresh_interval = Duration::from_secs(args.refresh_interval);
    tokio::spawn(async move {
        lease_refresh_loop(refresh_state, &refresh_path, refresh_interval).await;
    });

    // Bind listeners.
    let explicit_listener = match TcpListener::bind(("127.0.0.1", args.port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to bind explicit proxy on port {}: {e}", args.port);
            return ExitCode::FAILURE;
        }
    };

    let transparent_listener = match TcpListener::bind(("127.0.0.1", args.transparent_port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "error: failed to bind transparent proxy on port {}: {e}",
                args.transparent_port
            );
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        explicit_port = args.port,
        transparent_port = args.transparent_port,
        lease_file = %args.lease_file.display(),
        "proxy started"
    );

    // Run both listeners concurrently.
    let explicit_state = Arc::clone(&state);
    let transparent_state = Arc::clone(&state);

    tokio::select! {
        result = accept_explicit(explicit_listener, explicit_state) => {
            eprintln!("error: explicit proxy exited: {result:?}");
        }
        result = accept_transparent(transparent_listener, transparent_state) => {
            eprintln!("error: transparent proxy exited: {result:?}");
        }
    }

    ExitCode::FAILURE
}

/// Accept loop for the explicit CONNECT proxy.
async fn accept_explicit(
    listener: TcpListener,
    state: SharedLeaseState,
) -> std::io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = connect::handle_connect(stream, peer_addr, &state).await {
                tracing::debug!(peer = %peer_addr, error = %e, "connect handler error");
            }
        });
    }
}

/// Accept loop for the transparent proxy (SNI extraction).
async fn accept_transparent(
    listener: TcpListener,
    state: SharedLeaseState,
) -> std::io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = sni::handle_transparent(stream, peer_addr, &state).await {
                tracing::debug!(peer = %peer_addr, error = %e, "transparent handler error");
            }
        });
    }
}

/// Background task that reloads the lease state file periodically.
async fn lease_refresh_loop(
    state: SharedLeaseState,
    path: &std::path::Path,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;

        match LeaseState::read_from(path) {
            Ok(new_state) => {
                let mut guard = state.write().await;
                *guard = new_state;
                guard.prune_expired();
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to reload lease state");
                // Keep existing state — don't clear on read failure.
            }
        }
    }
}
