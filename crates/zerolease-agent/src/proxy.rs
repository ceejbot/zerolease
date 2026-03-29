//! Lease-aware HTTPS CONNECT proxy.
//!
//! Two modes:
//! - **Explicit proxy** (port 8080): Handles HTTP CONNECT requests.
//!   Tools reach it via HTTPS_PROXY env var.
//! - **Transparent proxy** (port 8443): Handles iptables-redirected
//!   TLS connections. Extracts domain from TLS SNI. Defense-in-depth.
//!
//! Both modes check the lease state before allowing a connection.
//! If the domain has no active lease, the connection is blocked.

use std::path::PathBuf;
use std::process::ExitCode;

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
}

pub async fn run(args: ProxyArgs) -> ExitCode {
    tracing::info!(
        port = args.port,
        transparent_port = args.transparent_port,
        lease_file = %args.lease_file.display(),
        "starting lease-aware proxy"
    );

    // TODO: implement proxy
    // 1. Load lease state from file
    // 2. Start explicit proxy on args.port
    // 3. Start transparent proxy on args.transparent_port
    // 4. Background task: watch lease file for changes, prune expired
    // 5. On each CONNECT: check lease state, allow or deny
    // 6. If allowed: tokio::io::copy_bidirectional

    eprintln!("error: proxy not yet implemented");
    ExitCode::FAILURE
}
