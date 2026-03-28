//! Basic vault usage example.
//!
//! Demonstrates the core vault API: store a secret, request a lease,
//! and access the credential through the lease.
//!
//! Run with:
//!   ZEROLEASE_KEY=$(openssl rand -hex 32) cargo run --example basic_vault

use std::sync::Arc;

use zerolease::audit::AuditLog;
use zerolease::keysource::env::EnvVarSource;
use zerolease::lease::LeaseTerms;
use zerolease::policy::{AgentPattern, PolicyConfig, PolicyEngine, PolicyGrant, SecretPattern};
use zerolease::store::{CipherAlgorithm, SecretKind};
use zerolease::transport::PeerIdentity;
use zerolease::types::{AgentId, DomainScope, SecretName};
use zerolease::vault::Vault;
use zerolease_store_rusqlite::RusqliteStore;

/// A no-op audit log for this example. In production, use SqliteAuditLog
/// or configure a tracing subscriber to capture audit events.
struct NoopAuditLog;

#[async_trait::async_trait]
impl AuditLog for NoopAuditLog {
    async fn record(&self, _: zerolease::audit::AuditEntry) -> zerolease::error::Result<()> {
        Ok(())
    }
    async fn query_by_agent(
        &self,
        _: &AgentId,
        _: usize,
    ) -> zerolease::error::Result<Vec<zerolease::audit::AuditEntry>> {
        Ok(vec![])
    }
    async fn query_by_secret(
        &self,
        _: &SecretName,
        _: usize,
    ) -> zerolease::error::Result<Vec<zerolease::audit::AuditEntry>> {
        Ok(vec![])
    }
    async fn query_by_lease(
        &self,
        _: &zerolease::types::LeaseId,
    ) -> zerolease::error::Result<Vec<zerolease::audit::AuditEntry>> {
        Ok(vec![])
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- 1. Set up the vault ---

    // The DEK comes from an environment variable (hex-encoded, 32 bytes).
    // In production, use KeychainSource or KmsSource instead.
    let key_source = EnvVarSource::new("ZEROLEASE_KEY");

    // SQLite for secret storage (single-file, zero-config).
    let store = RusqliteStore::new("example-secrets.db").await?;

    // Policy: allow "my-agent" to access "github-pat" for github.com
    let policy = PolicyEngine::new(PolicyConfig {
        default_lease_terms: LeaseTerms::default_short(), // 15 min, non-renewable
        grants: vec![PolicyGrant {
            agent: AgentPattern::Exact(AgentId::new("my-agent")),
            secret: SecretPattern::Exact(SecretName::new("github-pat")),
            allowed_domains: vec![DomainScope::new("*.github.com")],
            lease_terms: None, // use default
        }],
    });

    let vault = Arc::new(Vault::new(
        key_source,
        store,
        NoopAuditLog,
        policy,
        CipherAlgorithm::Aes256Gcm,
    ));

    // Initialize: loads or creates the DEK
    vault.initialize().await?;
    println!("vault initialized");

    // --- 2. Store a secret ---

    let peer = PeerIdentity::Anonymous;
    let metadata = vault
        .store_secret(
            &SecretName::new("github-pat"),
            b"ghp_exampletoken123456789",
            SecretKind::Pat,
            Some("GitHub PAT for CI".into()),
            &peer,
        )
        .await?;

    println!("stored secret: {} (version {})", metadata.name, metadata.version);

    // --- 3. Request a lease ---

    let grant = vault
        .request_lease(
            &AgentId::new("my-agent"),
            &SecretName::new("github-pat"),
            &DomainScope::new("api.github.com"),
            &peer,
        )
        .await?;

    println!("lease granted: {} (expires {})", grant.lease_id, grant.expires_at);

    // --- 4. Access the secret through the lease ---

    let guard = vault.access_secret(&grant.lease_id, "api.github.com", &peer).await?;

    guard.expose(|secret| {
        println!("secret value: {secret}");
    });

    // The guard is dropped here, zeroizing the secret from memory.

    // --- 5. Try accessing for the wrong domain (should fail) ---

    let result = vault.access_secret(&grant.lease_id, "evil.example.com", &peer).await;

    match result {
        Ok(_) => println!("BUG: access should have been denied!"),
        Err(e) => println!("correctly denied: {e}"),
    }

    // Clean up
    std::fs::remove_file("example-secrets.db").ok();

    println!("\ndone!");
    Ok(())
}
