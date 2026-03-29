//! Integration tests for session lifecycle, tool-to-secret bindings,
//! scoped lease requests, and audit hash chain verification.

use chrono::TimeDelta;
use zerolease::audit::{AuditEntry, AuditEvent, AuditLog, AuditOutcome};
use zerolease::keysource::env::EnvVarSource;
use zerolease::policy::{PolicyConfig, PolicyEngine, PolicyGrant};
use zerolease::session::{SessionPolicy, ToolCredentialBinding};
use zerolease::store::CipherAlgorithm;
use zerolease::transport::PeerIdentity;
use zerolease::types::{AgentId, DomainScope, LeaseTerms, SecretName, SessionToken};
use zerolease::vault::Vault;
use zerolease_store_rusqlite::{RusqliteAuditLog, RusqliteStore};

/// Set up an env var key source with a deterministic test key.
#[allow(unsafe_code)]
fn setup_env_key() {
    // SAFETY: tests run sequentially (no parallel env var mutation).
    unsafe {
        std::env::set_var(
            "ZEROLEASE_TEST_DEK",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
    }
}

/// Build a test vault with rusqlite backends.
async fn test_vault() -> Vault<EnvVarSource, RusqliteStore, RusqliteAuditLog> {
    setup_env_key();
    let key_source = EnvVarSource::new("ZEROLEASE_TEST_DEK");

    let store_tmp = tempfile::NamedTempFile::new().expect("temp file");
    let store = RusqliteStore::new(store_tmp.path()).await.expect("store");

    let audit_tmp = tempfile::NamedTempFile::new().expect("temp file");
    let audit = RusqliteAuditLog::new(audit_tmp.path()).await.expect("audit");

    let policy = PolicyEngine::new(PolicyConfig {
        default_lease_terms: LeaseTerms::default_short(),
        grants: vec![PolicyGrant {
            agent: zerolease::policy::AgentPattern::Any,
            secret: zerolease::policy::SecretPattern::Any,
            allowed_domains: vec![
                DomainScope::new("*.atlassian.net"),
                DomainScope::new("api.github.com"),
                DomainScope::new("github.com"),
                DomainScope::new("api.notion.com"),
            ],
            lease_terms: Some(LeaseTerms {
                ttl: TimeDelta::minutes(5),
                renewable: true,
                max_uses: None,
            }),
        }],
    });

    let vault = Vault::new(key_source, store, audit, policy, CipherAlgorithm::Aes256Gcm);
    vault.initialize().await.expect("init");

    // Store test secrets
    let peer = PeerIdentity::Anonymous;
    vault
        .store_secret(
            &SecretName::new("jira-pat"),
            b"jira-secret-value",
            zerolease::store::SecretKind::Pat,
            None,
            &peer,
        )
        .await
        .expect("store jira-pat");
    vault
        .store_secret(
            &SecretName::new("github-pat"),
            b"github-secret-value",
            zerolease::store::SecretKind::Pat,
            None,
            &peer,
        )
        .await
        .expect("store github-pat");

    vault
}

fn test_session_policy() -> SessionPolicy {
    SessionPolicy {
        max_session_duration: TimeDelta::hours(1),
        max_concurrent_leases: 3,
        max_renewals_per_lease: 2,
        tool_bindings: vec![
            ToolCredentialBinding {
                tool_name: "jira".into(),
                allowed_secrets: vec![SecretName::new("jira-pat")],
                allowed_domains: vec![DomainScope::new("*.atlassian.net")],
            },
            ToolCredentialBinding {
                tool_name: "github".into(),
                allowed_secrets: vec![SecretName::new("github-pat")],
                allowed_domains: vec![
                    DomainScope::new("api.github.com"),
                    DomainScope::new("github.com"),
                ],
            },
        ],
    }
}

// -- Session lifecycle --

#[tokio::test]
async fn session_create_validate_revoke() {
    let vault = test_vault().await;
    let peer = PeerIdentity::Anonymous;

    let (token, session_id) = vault
        .create_session("ceej", "telegram", test_session_policy(), &peer)
        .await
        .expect("create session");

    // Validate
    let session = vault.validate_session(&token).await.expect("validate");
    assert_eq!(session.id, session_id);
    assert!(session.is_active());

    // Revoke
    vault.revoke_session(&token, &peer).await.expect("revoke");

    // Validate after revoke should fail
    let result = vault.validate_session(&token).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn session_token_lookup_rejects_random_bytes() {
    let vault = test_vault().await;
    let fake_token = SessionToken::from_bytes([0xDE; 16]);
    let result = vault.validate_session(&fake_token).await;
    assert!(result.is_err());
}

// -- Tool-to-secret bindings --

#[tokio::test]
async fn scoped_lease_allows_matching_binding() {
    let vault = test_vault().await;
    let peer = PeerIdentity::Anonymous;

    let (token, _) = vault
        .create_session("ceej", "telegram", test_session_policy(), &peer)
        .await
        .expect("create session");

    // jira tool requesting jira-pat → allowed
    let grant = vault
        .request_lease_scoped(
            &AgentId::new("tool-jira"),
            &SecretName::new("jira-pat"),
            &DomainScope::new("myco.atlassian.net"),
            &peer,
            &token,
            "jira",
        )
        .await;
    assert!(grant.is_ok());
}

#[tokio::test]
async fn scoped_lease_denies_wrong_secret_for_tool() {
    let vault = test_vault().await;
    let peer = PeerIdentity::Anonymous;

    let (token, _) = vault
        .create_session("ceej", "telegram", test_session_policy(), &peer)
        .await
        .expect("create session");

    // jira tool requesting github-pat → denied by tool binding
    let result = vault
        .request_lease_scoped(
            &AgentId::new("tool-jira"),
            &SecretName::new("github-pat"),
            &DomainScope::new("myco.atlassian.net"),
            &peer,
            &token,
            "jira",
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn scoped_lease_denies_wrong_domain_for_tool() {
    let vault = test_vault().await;
    let peer = PeerIdentity::Anonymous;

    let (token, _) = vault
        .create_session("ceej", "telegram", test_session_policy(), &peer)
        .await
        .expect("create session");

    // jira tool with correct secret but wrong domain → denied
    let result = vault
        .request_lease_scoped(
            &AgentId::new("tool-jira"),
            &SecretName::new("jira-pat"),
            &DomainScope::new("evil.example.com"),
            &peer,
            &token,
            "jira",
        )
        .await;
    assert!(result.is_err());
}

// -- Session expiry --

#[tokio::test]
async fn expired_session_rejects_lease_requests() {
    let vault = test_vault().await;
    let peer = PeerIdentity::Anonymous;

    let policy = SessionPolicy {
        max_session_duration: TimeDelta::milliseconds(1),
        ..test_session_policy()
    };

    let (token, _) = vault
        .create_session("ceej", "telegram", policy, &peer)
        .await
        .expect("create session");

    // Wait for expiry
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let result = vault
        .request_lease_scoped(
            &AgentId::new("tool-jira"),
            &SecretName::new("jira-pat"),
            &DomainScope::new("myco.atlassian.net"),
            &peer,
            &token,
            "jira",
        )
        .await;
    assert!(result.is_err());
}

// -- Session revocation cascades to child leases --

#[tokio::test]
async fn session_revocation_cascades_to_leases() {
    let vault = test_vault().await;
    let peer = PeerIdentity::Anonymous;

    let (token, _) = vault
        .create_session("ceej", "telegram", test_session_policy(), &peer)
        .await
        .expect("create session");

    // Create a scoped lease
    let grant = vault
        .request_lease_scoped(
            &AgentId::new("tool-jira"),
            &SecretName::new("jira-pat"),
            &DomainScope::new("myco.atlassian.net"),
            &peer,
            &token,
            "jira",
        )
        .await
        .expect("scoped lease");

    // Revoke session
    vault.revoke_session(&token, &peer).await.expect("revoke");

    // The lease should be revoked — accessing the secret should fail
    let result = vault
        .access_secret(&grant.lease_id, "myco.atlassian.net", &peer)
        .await;
    assert!(result.is_err());
}

// -- Concurrent lease limit --

#[tokio::test]
async fn max_concurrent_leases_enforced() {
    let vault = test_vault().await;
    let peer = PeerIdentity::Anonymous;

    let policy = SessionPolicy {
        max_concurrent_leases: 2,
        ..test_session_policy()
    };

    let (token, _) = vault
        .create_session("ceej", "telegram", policy, &peer)
        .await
        .expect("create session");

    // Lease 1: ok
    vault
        .request_lease_scoped(
            &AgentId::new("tool-jira"),
            &SecretName::new("jira-pat"),
            &DomainScope::new("myco.atlassian.net"),
            &peer,
            &token,
            "jira",
        )
        .await
        .expect("lease 1");

    // Lease 2: ok
    vault
        .request_lease_scoped(
            &AgentId::new("tool-github"),
            &SecretName::new("github-pat"),
            &DomainScope::new("api.github.com"),
            &peer,
            &token,
            "github",
        )
        .await
        .expect("lease 2");

    // Lease 3: should fail (limit is 2)
    let result = vault
        .request_lease_scoped(
            &AgentId::new("tool-jira"),
            &SecretName::new("jira-pat"),
            &DomainScope::new("myco.atlassian.net"),
            &peer,
            &token,
            "jira",
        )
        .await;
    assert!(result.is_err());
}

// -- Max renewals per lease --

#[tokio::test]
async fn max_renewals_per_lease_enforced() {
    let vault = test_vault().await;
    let peer = PeerIdentity::Anonymous;

    let policy = SessionPolicy {
        max_renewals_per_lease: 2,
        ..test_session_policy()
    };

    let (token, _) = vault
        .create_session("ceej", "telegram", policy, &peer)
        .await
        .expect("create session");

    let grant = vault
        .request_lease_scoped(
            &AgentId::new("tool-jira"),
            &SecretName::new("jira-pat"),
            &DomainScope::new("myco.atlassian.net"),
            &peer,
            &token,
            "jira",
        )
        .await
        .expect("scoped lease");

    // Renewal 1: ok
    vault.renew_lease(&grant.lease_id, 60, &peer).await.expect("renew 1");

    // Renewal 2: ok
    vault.renew_lease(&grant.lease_id, 60, &peer).await.expect("renew 2");

    // Renewal 3: should fail (limit is 2)
    let result = vault.renew_lease(&grant.lease_id, 60, &peer).await;
    assert!(result.is_err());
}

// -- Existing request_lease without session still works --

#[tokio::test]
async fn request_lease_without_session_unchanged() {
    let vault = test_vault().await;
    let peer = PeerIdentity::Anonymous;

    let grant = vault
        .request_lease(
            &AgentId::new("legacy-agent"),
            &SecretName::new("jira-pat"),
            &DomainScope::new("myco.atlassian.net"),
            &peer,
        )
        .await;
    assert!(grant.is_ok());
}

// -- Session GC --

#[tokio::test]
async fn gc_removes_expired_sessions() {
    let vault = test_vault().await;
    let peer = PeerIdentity::Anonymous;

    let policy = SessionPolicy {
        max_session_duration: TimeDelta::milliseconds(1),
        ..test_session_policy()
    };

    vault
        .create_session("ceej", "telegram", policy, &peer)
        .await
        .expect("create session");

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let removed = vault.gc_sessions().await;
    assert_eq!(removed, 1);
}

// -- Audit hash chain --

#[tokio::test]
async fn audit_chain_valid_after_operations() {
    let audit_tmp = tempfile::NamedTempFile::new().expect("temp file");
    let audit = RusqliteAuditLog::new(audit_tmp.path()).await.expect("audit");

    // Record several entries
    let peer = PeerIdentity::Anonymous;
    for i in 0..5 {
        audit
            .record(AuditEntry::new(
                AuditEvent::DekRotated,
                AgentId::new(format!("agent-{i}")),
                &peer,
                AuditOutcome::Success,
            ))
            .await
            .expect("record");
    }

    // Verify chain
    let verification = audit.verify_audit_chain().await.expect("verify");
    assert!(verification.is_valid, "chain should be valid");
    assert_eq!(verification.total_entries, 5);
    assert_eq!(verification.verified_entries, 5);
    assert!(verification.first_broken_at.is_none());
}

#[tokio::test]
async fn audit_chain_detects_tampered_entry() {
    let audit_tmp = tempfile::NamedTempFile::new().expect("temp file");
    let audit = RusqliteAuditLog::new(audit_tmp.path()).await.expect("audit");

    let peer = PeerIdentity::Anonymous;
    for i in 0..3 {
        audit
            .record(AuditEntry::new(
                AuditEvent::DekRotated,
                AgentId::new(format!("agent-{i}")),
                &peer,
                AuditOutcome::Success,
            ))
            .await
            .expect("record");
    }

    // Tamper with the second entry's hash
    {
        let conn = rusqlite::Connection::open(audit_tmp.path()).expect("open");
        conn.execute(
            "UPDATE audit_events SET entry_hash = 'tampered' WHERE agent = 'agent-1'",
            [],
        )
        .expect("tamper");
    }

    let verification = audit.verify_audit_chain().await.expect("verify");
    assert!(!verification.is_valid, "chain should be invalid after tampering");
    assert!(verification.first_broken_at.is_some());
}
