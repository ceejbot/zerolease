//! Core identity and domain types used throughout zerolease.
//!
//! These are the foundational newtypes that give us compile-time
//! distinction between different kinds of identifiers. Using newtypes
//! rather than bare `Uuid`s prevents accidentally passing an `AgentId`
//! where a `SecretId` is expected.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a stored secret.
///
/// Generated server-side when a secret is first stored. Opaque to
/// agents—they request secrets by name + scope, not by raw ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretId(Uuid);

impl SecretId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "secret:{}", self.0)
    }
}

/// Identity of an agent requesting credentials.
///
/// On Firecracker/QEMU, this is derived from the VM's workload identity
/// (e.g., a CID or a token issued at boot). On developer laptops, this
/// may be a static identifier for the local agent process.
///
/// AgentId is the principal in all policy checks and audit log entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(String);

impl AgentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "agent:{}", self.0)
    }
}

/// Unique identifier for an active lease.
///
/// Returned to the agent when a lease is granted. The agent presents
/// this to access the credential and the vault uses it for revocation
/// and audit correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeaseId(Uuid);

impl LeaseId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for LeaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LeaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lease:{}", self.0)
    }
}

/// A human-readable name for a stored secret, used by agents to
/// request credentials. Names are scoped per-domain to avoid collisions.
///
/// Example: `SecretName("jira-api-token")`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretName(String);

impl SecretName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The target domain a credential is authorized to be used against.
///
/// This is the key mechanism preventing lateral movement: a Jira PAT
/// can only be injected into requests to `*.atlassian.net`, not
/// exfiltrated to `evil.example.com`.
///
/// Patterns support:
/// - Exact match: `api.github.com`
/// - Wildcard subdomain: `*.atlassian.net`
/// - Localhost with port (for sidecar/proxy patterns): `localhost:8080`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainScope(String);

impl DomainScope {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// Check whether a target host matches this scope.
    pub fn matches(&self, host: &str) -> bool {
        let pattern = &self.0;

        if pattern == host {
            return true;
        }

        // Wildcard subdomain matching: *.example.com matches
        // foo.example.com and bar.baz.example.com
        if let Some(suffix) = pattern.strip_prefix("*.")
            && let Some(rest) = host.strip_suffix(suffix)
        {
            // Ensure there's a proper subdomain: at least one character
            // before the trailing dot (e.g., "foo." not just ".").
            return rest.ends_with('.') && rest.len() > 1;
        }

        false
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DomainScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_scope_exact_match() {
        let scope = DomainScope::new("api.github.com");
        assert!(scope.matches("api.github.com"));
        assert!(!scope.matches("evil.example.com"));
        assert!(!scope.matches("github.com"));
    }

    #[test]
    fn domain_scope_wildcard_match() {
        let scope = DomainScope::new("*.atlassian.net");
        assert!(scope.matches("mycompany.atlassian.net"));
        assert!(scope.matches("api.mycompany.atlassian.net"));
        assert!(!scope.matches("atlassian.net")); // bare domain should NOT match wildcard
        assert!(!scope.matches("evil.example.com"));
    }

    #[test]
    fn domain_scope_localhost_exact() {
        let scope = DomainScope::new("localhost:8080");
        assert!(scope.matches("localhost:8080"));
        assert!(!scope.matches("localhost:9090"));
    }

    #[test]
    fn secret_id_display_is_prefixed() {
        let id = SecretId::new();
        let s = id.to_string();
        assert!(s.starts_with("secret:"));
    }

    #[test]
    fn newtype_ids_are_not_interchangeable() {
        // This is a compile-time guarantee, but we document the intent:
        // SecretId, AgentId, and LeaseId are distinct types. You cannot
        // accidentally pass one where another is expected.
        let _secret = SecretId::new();
        let _lease = LeaseId::new();
        let _agent = AgentId::new("test-agent");
        // If these were all Uuid, you could mix them up. Newtypes prevent that.
    }
}
