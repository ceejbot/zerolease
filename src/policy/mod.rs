//! Credential access policies: who can access what, for which domains.
//!
//! Policies are the authorization layer between an agent's request and
//! the vault's secret store. Every lease request is evaluated against
//! the policy engine before any cryptographic operations occur.
//!
//! The policy model is deny-by-default: an agent has no access to any
//! secret unless an explicit policy grants it.
//!
//! ## Design rationale
//!
//! We use a simple, auditable policy format rather than a full-blown
//! policy language (like OPA/Rego or Cedar). The threat model is
//! "agents running tools that need specific credentials for specific
//! services," not "arbitrary multi-tenant RBAC." A flat list of
//! grant rules is easier to audit, easier to understand, and harder
//! to misconfigure.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::lease::LeaseTerms;
use crate::types::{AgentId, DomainScope, SecretName};

/// A single policy rule granting an agent access to a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGrant {
    /// Which agent this grant applies to.
    pub agent: AgentPattern,

    /// Which secret(s) this grant covers.
    pub secret: SecretPattern,

    /// Which domain(s) the credential may be used against.
    pub allowed_domains: Vec<DomainScope>,

    /// Lease terms to apply when this grant is matched.
    /// If None, uses the vault's default lease terms.
    pub lease_terms: Option<LeaseTerms>,
}

/// Pattern for matching agent identities in policy rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentPattern {
    /// Match a single specific agent by ID.
    Exact(AgentId),

    /// Match agents whose ID starts with a prefix.
    /// Useful for `ci-agent-*` or `dev-*` patterns.
    Prefix(String),

    /// Match any agent. Use with extreme caution.
    Any,
}

impl AgentPattern {
    pub fn matches(&self, agent: &AgentId) -> bool {
        match self {
            AgentPattern::Exact(id) => id == agent,
            AgentPattern::Prefix(prefix) => agent.as_str().starts_with(prefix),
            AgentPattern::Any => true,
        }
    }
}

/// Pattern for matching secret names in policy rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretPattern {
    /// Match a single specific secret by name.
    Exact(SecretName),

    /// Match secrets whose name starts with a prefix.
    /// Useful for `jira-*` or `aws-*` groupings.
    Prefix(String),

    /// Match any secret. Use with extreme caution.
    Any,
}

impl SecretPattern {
    pub fn matches(&self, name: &SecretName) -> bool {
        match self {
            SecretPattern::Exact(n) => n == name,
            SecretPattern::Prefix(prefix) => name.as_str().starts_with(prefix),
            SecretPattern::Any => true,
        }
    }
}

/// The complete policy configuration for the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Default lease terms if a matching grant doesn't specify its own.
    pub default_lease_terms: LeaseTerms,

    /// The list of grant rules, evaluated in order.
    /// First match wins.
    pub grants: Vec<PolicyGrant>,
}

impl PolicyConfig {
    /// Load a policy configuration from a JSON file.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            crate::error::Error::InvalidConfig(format!("failed to read policy file: {e}"))
        })?;
        Self::from_json(&contents)
    }

    /// Parse a policy configuration from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| crate::error::Error::InvalidConfig(format!("invalid policy JSON: {e}")))
    }
}

/// The policy engine evaluates access requests against the configured rules.
pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        // Validate grants and warn on potentially dangerous patterns
        for (i, grant) in config.grants.iter().enumerate() {
            if let AgentPattern::Prefix(p) = &grant.agent
                && p.is_empty()
            {
                tracing::warn!(
                    grant_index = i,
                    "policy grant has empty AgentPattern::Prefix, matches all agents"
                );
            }
            if let SecretPattern::Prefix(p) = &grant.secret
                && p.is_empty()
            {
                tracing::warn!(
                    grant_index = i,
                    "policy grant has empty SecretPattern::Prefix, matches all secrets"
                );
            }
            for domain in &grant.allowed_domains {
                let ds = domain.as_str();
                if ds.is_empty() {
                    tracing::warn!(grant_index = i, "policy grant has empty DomainScope pattern");
                } else if ds == "*." {
                    tracing::warn!(
                        grant_index = i,
                        domain = ds,
                        "policy grant has malformed DomainScope '*.' (matches nothing)"
                    );
                } else if ds.chars().any(|c| c.is_whitespace()) {
                    tracing::warn!(
                        grant_index = i,
                        domain = ds,
                        "policy grant DomainScope contains whitespace"
                    );
                }
            }
        }
        Self { config }
    }

    /// Evaluate whether an agent may access a secret for a given domain.
    /// Returns the applicable lease terms if access is granted.
    pub fn evaluate(&self, agent: &AgentId, secret: &SecretName, domain: &DomainScope) -> Result<LeaseTerms> {
        for grant in &self.config.grants {
            if !grant.agent.matches(agent) {
                continue;
            }
            if !grant.secret.matches(secret) {
                continue;
            }
            if !grant.allowed_domains.iter().any(|d| d.matches(domain.as_str())) {
                continue;
            }

            // Match found. Return the grant-specific terms or the default.
            let terms = grant
                .lease_terms
                .clone()
                .unwrap_or_else(|| self.config.default_lease_terms.clone());

            tracing::info!(
                agent = %agent,
                secret = %secret,
                domain = %domain,
                "policy: access granted"
            );

            return Ok(terms);
        }

        tracing::warn!(
            agent = %agent,
            secret = %secret,
            domain = %domain,
            "policy: access denied (no matching grant)"
        );

        Err(Error::AccessDenied {
            agent: agent.clone(),
            secret: secret.clone(),
            domain: domain.clone(),
        })
    }

    /// List all grants that apply to a specific agent (for introspection).
    pub fn grants_for_agent(&self, agent: &AgentId) -> Vec<&PolicyGrant> {
        self.config.grants.iter().filter(|g| g.agent.matches(agent)).collect()
    }

    /// Reload policy from a new config. This is intentionally a full
    /// replacement rather than incremental mutation—easier to reason
    /// about and audit.
    pub fn reload(&mut self, config: PolicyConfig) {
        tracing::info!(grant_count = config.grants.len(), "policy engine reloaded");
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PolicyConfig {
        PolicyConfig {
            default_lease_terms: LeaseTerms::default_short(),
            grants: vec![
                PolicyGrant {
                    agent: AgentPattern::Exact(AgentId::new("ci-agent-1")),
                    secret: SecretPattern::Exact(SecretName::new("github-pat")),
                    allowed_domains: vec![DomainScope::new("api.github.com")],
                    lease_terms: Some(LeaseTerms::single_use()),
                },
                PolicyGrant {
                    agent: AgentPattern::Prefix("dev-".to_string()),
                    secret: SecretPattern::Prefix("jira-".to_string()),
                    allowed_domains: vec![DomainScope::new("*.atlassian.net")],
                    lease_terms: None, // uses default
                },
            ],
        }
    }

    #[test]
    fn exact_match_grants_access() {
        let engine = PolicyEngine::new(test_config());
        let result = engine.evaluate(
            &AgentId::new("ci-agent-1"),
            &SecretName::new("github-pat"),
            &DomainScope::new("api.github.com"),
        );
        assert!(result.is_ok());
        // Should get single-use terms from the grant
        let terms = result.expect("exact match should grant access");
        assert_eq!(terms.max_uses, Some(1));
    }

    #[test]
    fn prefix_match_grants_access() {
        let engine = PolicyEngine::new(test_config());
        let result = engine.evaluate(
            &AgentId::new("dev-alice"),
            &SecretName::new("jira-api-token"),
            &DomainScope::new("mycompany.atlassian.net"),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn wrong_domain_denies_access() {
        let engine = PolicyEngine::new(test_config());
        let result = engine.evaluate(
            &AgentId::new("ci-agent-1"),
            &SecretName::new("github-pat"),
            &DomainScope::new("evil.example.com"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn unknown_agent_denied() {
        let engine = PolicyEngine::new(test_config());
        let result = engine.evaluate(
            &AgentId::new("rogue-agent"),
            &SecretName::new("github-pat"),
            &DomainScope::new("api.github.com"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn deny_by_default() {
        let engine = PolicyEngine::new(PolicyConfig {
            default_lease_terms: LeaseTerms::default_short(),
            grants: vec![],
        });
        let result = engine.evaluate(
            &AgentId::new("any-agent"),
            &SecretName::new("any-secret"),
            &DomainScope::new("any.domain.com"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn policy_config_round_trips_through_json() {
        let config = test_config();
        let json = serde_json::to_string_pretty(&config).expect("serialize");
        let parsed = PolicyConfig::from_json(&json).expect("parse");
        assert_eq!(parsed.grants.len(), config.grants.len(), "grant count should match");
    }

    #[test]
    fn policy_config_from_json_with_all_patterns() {
        // TimeDelta serializes as a [secs, nanos] tuple.
        let json = r#"{
            "default_lease_terms": { "ttl": [900, 0], "renewable": false, "max_uses": null },
            "grants": [
                {
                    "agent": { "Exact": "tool-git" },
                    "secret": { "Exact": "github-pat" },
                    "allowed_domains": ["github.com"],
                    "lease_terms": { "ttl": [300, 0], "renewable": false, "max_uses": 5 }
                },
                {
                    "agent": { "Prefix": "ci-" },
                    "secret": "Any",
                    "allowed_domains": ["*.internal.example.com"],
                    "lease_terms": null
                }
            ]
        }"#;

        let config = PolicyConfig::from_json(json).expect("should parse JSON policy");
        assert_eq!(config.grants.len(), 2, "should have 2 grants");

        let engine = PolicyEngine::new(config);
        assert!(
            engine.evaluate(&AgentId::new("tool-git"), &SecretName::new("github-pat"), &DomainScope::new("github.com")).is_ok(),
            "exact match should grant access"
        );
        assert!(
            engine.evaluate(&AgentId::new("ci-runner"), &SecretName::new("anything"), &DomainScope::new("db.internal.example.com")).is_ok(),
            "prefix + Any + wildcard domain should grant access"
        );
    }

    #[test]
    fn policy_config_invalid_json_errors() {
        assert!(PolicyConfig::from_json("not json").is_err());
    }
}
