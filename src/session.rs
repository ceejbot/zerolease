//! Session types: trust contexts that scope credential access.
//!
//! A session binds credential access to a user-initiated work unit
//! (typically a conversation). Sessions are created when a trusted user
//! sends a message, and revoked when the conversation ends, the user
//! disconnects, or the session's TTL expires.
//!
//! Sessions enforce:
//! - **Tool-to-secret bindings:** which tools can access which secrets
//! - **Lease lifetime caps:** `max_renewals_per_lease`
//! - **Concurrency limits:** `max_concurrent_leases`
//! - **Absolute duration:** `max_session_duration`

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::{DomainScope, SecretName, SessionId};

/// A live session on the vault.
///
/// Sessions group leases under a common trust context. When a session
/// is revoked, all child leases are revoked with it.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: SessionId,
    /// Who initiated this session (from trusted user authentication).
    pub user: String,
    /// Originating channel (e.g., "telegram", "api", "cli").
    pub channel: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub policy: SessionPolicy,
    /// Number of currently active (non-revoked, non-expired) leases
    /// under this session. Maintained by the vault when granting and
    /// revoking leases.
    pub active_lease_count: u32,
    pub revoked: bool,
}

impl Session {
    /// Create a new session with the given policy.
    pub fn new(user: impl Into<String>, channel: impl Into<String>, policy: SessionPolicy) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::new(),
            user: user.into(),
            channel: channel.into(),
            created_at: now,
            expires_at: now + policy.max_session_duration,
            policy,
            active_lease_count: 0,
            revoked: false,
        }
    }

    /// Whether this session has expired (TTL exceeded).
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Whether this session is still usable (not revoked, not expired).
    pub fn is_active(&self) -> bool {
        !self.revoked && !self.is_expired()
    }

    /// Time remaining before expiration.
    pub fn time_remaining(&self) -> TimeDelta {
        self.expires_at - Utc::now()
    }

    /// Revoke this session. Child lease revocation is handled by the vault.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Check whether a tool-to-secret binding allows this access.
    ///
    /// Looks for a `ToolCredentialBinding` where:
    /// - `tool_name` matches
    /// - `allowed_secrets` contains `secret_name`
    /// - `allowed_domains` contains a pattern matching `domain`
    ///
    /// Returns `Ok(())` if allowed, `Err` if denied.
    pub fn check_tool_binding(
        &self,
        tool_name: &str,
        secret_name: &SecretName,
        domain: &DomainScope,
    ) -> Result<()> {
        for binding in &self.policy.tool_bindings {
            if binding.tool_name != tool_name {
                continue;
            }
            let secret_ok = binding.allowed_secrets.iter().any(|s| s == secret_name);
            let domain_ok = binding.allowed_domains.iter().any(|d| d.matches(domain.as_str()));
            if secret_ok && domain_ok {
                return Ok(());
            }
        }

        Err(Error::AccessDenied {
            agent: crate::types::AgentId::new(tool_name),
            secret: secret_name.clone(),
            domain: domain.clone(),
        })
    }
}

/// Policy governing a session's credential access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPolicy {
    /// Absolute hard cap on session duration. Non-renewable.
    pub max_session_duration: TimeDelta,
    /// Maximum number of simultaneously active leases under this session.
    pub max_concurrent_leases: u32,
    /// Maximum number of times any single lease can be renewed.
    pub max_renewals_per_lease: u32,
    /// Which tools can access which secrets and domains.
    pub tool_bindings: Vec<ToolCredentialBinding>,
}

impl SessionPolicy {
    /// A reasonable default for development and testing.
    pub fn default_dev() -> Self {
        Self {
            max_session_duration: TimeDelta::hours(1),
            max_concurrent_leases: 10,
            max_renewals_per_lease: 3,
            tool_bindings: Vec::new(), // no bindings = no tool restrictions
        }
    }
}

/// Binds a tool name to the secrets and domains it may access.
///
/// In a session with tool bindings, every lease request must match a
/// binding for the invoking tool. A tool not listed in any binding
/// cannot acquire any credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCredentialBinding {
    /// The tool name as known to the orchestrator (e.g., "jira", "github").
    pub tool_name: String,
    /// Secrets this tool is allowed to request.
    pub allowed_secrets: Vec<SecretName>,
    /// Domains this tool is allowed to target.
    pub allowed_domains: Vec<DomainScope>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> SessionPolicy {
        SessionPolicy {
            max_session_duration: TimeDelta::hours(1),
            max_concurrent_leases: 5,
            max_renewals_per_lease: 3,
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

    #[test]
    fn session_is_active_when_new() {
        let session = Session::new("ceej", "telegram", test_policy());
        assert!(session.is_active());
        assert!(!session.is_expired());
        assert!(!session.revoked);
    }

    #[test]
    fn session_is_inactive_when_revoked() {
        let mut session = Session::new("ceej", "telegram", test_policy());
        session.revoke();
        assert!(!session.is_active());
        assert!(session.revoked);
    }

    #[test]
    fn session_is_inactive_when_expired() {
        let policy = SessionPolicy {
            max_session_duration: TimeDelta::seconds(-1), // already expired
            ..test_policy()
        };
        let session = Session::new("ceej", "telegram", policy);
        assert!(!session.is_active());
        assert!(session.is_expired());
    }

    #[test]
    fn tool_binding_allows_matching_access() {
        let session = Session::new("ceej", "telegram", test_policy());
        assert!(session
            .check_tool_binding("jira", &SecretName::new("jira-pat"), &DomainScope::new("myco.atlassian.net"))
            .is_ok());
    }

    #[test]
    fn tool_binding_denies_wrong_secret() {
        let session = Session::new("ceej", "telegram", test_policy());
        // jira tool trying to get github-pat → denied
        assert!(session
            .check_tool_binding("jira", &SecretName::new("github-pat"), &DomainScope::new("myco.atlassian.net"))
            .is_err());
    }

    #[test]
    fn tool_binding_denies_wrong_domain() {
        let session = Session::new("ceej", "telegram", test_policy());
        // jira tool with correct secret but wrong domain → denied
        assert!(session
            .check_tool_binding("jira", &SecretName::new("jira-pat"), &DomainScope::new("evil.example.com"))
            .is_err());
    }

    #[test]
    fn tool_binding_denies_unknown_tool() {
        let session = Session::new("ceej", "telegram", test_policy());
        // unknown tool → denied
        assert!(session
            .check_tool_binding("unknown-tool", &SecretName::new("jira-pat"), &DomainScope::new("myco.atlassian.net"))
            .is_err());
    }

    #[test]
    fn github_tool_matches_its_bindings() {
        let session = Session::new("ceej", "telegram", test_policy());
        assert!(session
            .check_tool_binding("github", &SecretName::new("github-pat"), &DomainScope::new("api.github.com"))
            .is_ok());
        assert!(session
            .check_tool_binding("github", &SecretName::new("github-pat"), &DomainScope::new("github.com"))
            .is_ok());
    }

    #[test]
    fn empty_bindings_deny_all_tools() {
        let policy = SessionPolicy {
            tool_bindings: Vec::new(),
            ..test_policy()
        };
        let session = Session::new("ceej", "telegram", policy);
        assert!(session
            .check_tool_binding("jira", &SecretName::new("jira-pat"), &DomainScope::new("myco.atlassian.net"))
            .is_err());
    }

    #[test]
    fn time_remaining_is_positive_for_active_session() {
        let session = Session::new("ceej", "telegram", test_policy());
        assert!(session.time_remaining().num_seconds() > 0);
    }
}
