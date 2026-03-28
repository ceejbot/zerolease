//! Credential manifest: describes which secrets to acquire and where
//! to inject them.
//!
//! The manifest is a JSON file injected into the VM alongside the
//! prompt-run token. Each entry maps a zerolease secret + target
//! domain to an environment variable name.

use serde::{Deserialize, Serialize};

/// A set of credentials to acquire from the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialManifest {
    pub credentials: Vec<CredentialEntry>,
}

/// A single credential to acquire and inject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    /// The zerolease secret name (e.g., "github-pat").
    pub secret_name: String,
    /// The domain this credential is scoped to (e.g., "github.com").
    pub target_domain: String,
    /// The environment variable to set (e.g., "GITHUB_TOKEN").
    pub env_var: String,
}

impl CredentialManifest {
    /// Parse a manifest from a JSON string.
    #[cfg(test)]
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Parse a manifest from a file path.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest() {
        let json = r#"{
            "credentials": [
                {
                    "secret_name": "github-pat",
                    "target_domain": "github.com",
                    "env_var": "GITHUB_TOKEN"
                },
                {
                    "secret_name": "jira-token",
                    "target_domain": "mycompany.atlassian.net",
                    "env_var": "JIRA_API_TOKEN"
                }
            ]
        }"#;

        let manifest = CredentialManifest::from_json(json).expect("should parse manifest");
        assert_eq!(manifest.credentials.len(), 2, "should have 2 entries");
        assert_eq!(manifest.credentials[0].secret_name, "github-pat");
        assert_eq!(manifest.credentials[0].env_var, "GITHUB_TOKEN");
        assert_eq!(manifest.credentials[1].target_domain, "mycompany.atlassian.net");
    }

    #[test]
    fn empty_manifest() {
        let json = r#"{ "credentials": [] }"#;
        let manifest = CredentialManifest::from_json(json).expect("should parse empty manifest");
        assert!(manifest.credentials.is_empty());
    }

    #[test]
    fn invalid_json_errors() {
        let result = CredentialManifest::from_json("not json");
        assert!(result.is_err());
    }
}
