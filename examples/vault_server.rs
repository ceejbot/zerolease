//! Example vault server with TCP transport and token authentication.
//!
//! Starts a vault server that accepts TCP connections with bearer
//! tokens. Useful for testing the TCP transport, the agent binary,
//! and client integrations.
//!
//! Run with:
//!   ZEROLEASE_KEY=$(openssl rand -hex 32) cargo run --example vault_server
//!
//! Then in another terminal:
//!   # The server prints the registered token on startup.
//!   # Use it with the agent or a VaultClient.

use std::sync::Arc;

use zerolease::audit::tracing_log::TracingAuditLog;
use zerolease::auth::{ConnectionIdentity, Role, TokenAuthenticator};
use zerolease::keysource::env::EnvVarSource;
use zerolease::lease::LeaseTerms;
use zerolease::policy::{AgentPattern, PolicyConfig, PolicyEngine, PolicyGrant, SecretPattern};
use zerolease::server::VaultServer;
use zerolease::store::{CipherAlgorithm, SecretKind};
use zerolease::transport::PeerIdentity;
use zerolease::transport::tcp::TcpListener;
use zerolease::types::{AgentId, DomainScope, SecretName};
use zerolease::vault::Vault;
use zerolease_store_rusqlite::RusqliteStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9100);

    // --- Backends ---

    let key_source = EnvVarSource::new("ZEROLEASE_KEY");
    let store = RusqliteStore::new("vault-server-example.db").await?;
    let audit = TracingAuditLog::new();

    // --- Policy ---
    // Allow any agent to access any secret for any domain.
    // In production, load from a file: PolicyConfig::from_file("policy.json")?

    let policy = PolicyEngine::new(PolicyConfig {
        default_lease_terms: LeaseTerms::default_short(),
        grants: vec![PolicyGrant {
            agent: AgentPattern::Any,
            secret: SecretPattern::Any,
            allowed_domains: vec![DomainScope::new("*")],
            lease_terms: None,
        }],
    });

    // --- Vault ---

    let vault = Vault::new(key_source, store, audit, policy, CipherAlgorithm::Aes256Gcm);
    vault.initialize().await?;

    // Store a test secret so there's something to lease.
    let _ = vault
        .store_secret(
            &SecretName::new("test-secret"),
            b"s3cr3t-value",
            SecretKind::Pat,
            Some("Test secret for the example server".into()),
            &PeerIdentity::Anonymous,
        )
        .await;

    let vault = Arc::new(vault);

    // --- Authentication ---
    // Register a token that grants admin access.

    let auth = TokenAuthenticator::new();
    let token = "example-admin-token";
    auth.register(
        token,
        ConnectionIdentity {
            role: Role::Admin,
            agent_id: None,
            label: "example-admin".to_string(),
        },
    );

    // Also register an agent token for testing.
    let agent_token = "example-agent-token";
    auth.register(
        agent_token,
        ConnectionIdentity {
            role: Role::Agent,
            agent_id: Some(AgentId::new("example-agent")),
            label: "example-agent".to_string(),
        },
    );

    let auth = Arc::new(auth);

    // --- Transport ---

    let listener = TcpListener::bind(port).await?;

    println!("vault server listening on 127.0.0.1:{port}");
    println!();
    println!("  Admin token:  {token}");
    println!("  Agent token:  {agent_token}");
    println!("  Test secret:  test-secret");
    println!();
    println!("Try:");
    println!("  # Store a secret (admin)");
    println!("  # Request a lease (agent)");
    println!("  # Access a secret through the lease");

    // --- Serve ---

    let server = VaultServer::new(vault, listener, auth);
    server.serve().await?;

    Ok(())
}
