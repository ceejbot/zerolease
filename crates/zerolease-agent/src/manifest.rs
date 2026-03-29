//! Credential manifest: describes which secrets to acquire and how
//! to inject them into the tool environment.
//!
//! The manifest is a JSON file injected into the VM alongside the
//! prompt-run token. Each credential entry specifies a vault secret,
//! a target domain, and one or more injection mechanisms (env vars,
//! config files, git credential helper mappings).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// A set of credentials to acquire from the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialManifest {
    pub credentials: Vec<CredentialEntry>,
}

/// A single credential to acquire and inject via one or more mechanisms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    /// The zerolease secret name (e.g., "github-pat").
    pub secret_name: String,
    /// The domain this credential is scoped to (e.g., "github.com").
    pub target_domain: String,
    /// How to make this credential available to tools.
    pub inject: Vec<InjectMechanism>,
}

/// A mechanism for injecting a credential into the tool environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InjectMechanism {
    /// Set an environment variable.
    #[serde(rename = "env")]
    Env { var: String },

    /// Write a config file with the secret interpolated.
    /// The `template` string uses `${SECRET}` as the placeholder.
    #[serde(rename = "file")]
    File { path: String, template: String },

    /// Register a git credential helper mapping: when git asks for
    /// this host, the credential helper returns this secret.
    #[serde(rename = "git_credential")]
    GitCredential { host: String },
}

impl CredentialManifest {
    /// Parse a manifest from a file path.
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        serde_json::from_str(&contents).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Build a lookup table from git host → (secret_name, target_domain)
    /// for use by the git credential helper.
    pub fn git_host_map(&self) -> HashMap<String, (&str, &str)> {
        let mut map = HashMap::new();
        for entry in &self.credentials {
            for mechanism in &entry.inject {
                if let InjectMechanism::GitCredential { host } = mechanism {
                    map.insert(host.clone(), (entry.secret_name.as_str(), entry.target_domain.as_str()));
                }
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_json(s: &str) -> Result<CredentialManifest, serde_json::Error> {
        serde_json::from_str(s)
    }

    #[test]
    fn parse_full_manifest() {
        let json = r#"{
            "credentials": [
                {
                    "secret_name": "github-pat",
                    "target_domain": "github.com",
                    "inject": [
                        { "type": "env", "var": "GITHUB_TOKEN" },
                        { "type": "env", "var": "GH_TOKEN" },
                        { "type": "git_credential", "host": "github.com" }
                    ]
                },
                {
                    "secret_name": "npm-token",
                    "target_domain": "registry.npmjs.org",
                    "inject": [
                        { "type": "env", "var": "NPM_TOKEN" },
                        { "type": "file", "path": "~/.npmrc", "template": "//registry.npmjs.org/:_authToken=${SECRET}" }
                    ]
                }
            ]
        }"#;

        let manifest = from_json(json).expect("should parse manifest");
        assert_eq!(manifest.credentials.len(), 2, "should have 2 entries");

        let github = &manifest.credentials[0];
        assert_eq!(github.secret_name, "github-pat");
        assert_eq!(github.target_domain, "github.com");
        assert_eq!(github.inject.len(), 3, "github should have 3 injection mechanisms");

        assert!(
            matches!(&github.inject[0], InjectMechanism::Env { var } if var == "GITHUB_TOKEN"),
            "first mechanism should be env GITHUB_TOKEN"
        );
        assert!(
            matches!(&github.inject[2], InjectMechanism::GitCredential { host } if host == "github.com"),
            "third mechanism should be git_credential for github.com"
        );

        let npm = &manifest.credentials[1];
        assert!(
            matches!(&npm.inject[1], InjectMechanism::File { path, template }
                if path == "~/.npmrc" && template.contains("${SECRET}")),
            "npm file injection should have template with SECRET placeholder"
        );
    }

    #[test]
    fn git_host_map_builds_correctly() {
        let manifest = from_json(
            r#"{
            "credentials": [
                {
                    "secret_name": "github-pat",
                    "target_domain": "github.com",
                    "inject": [
                        { "type": "git_credential", "host": "github.com" }
                    ]
                },
                {
                    "secret_name": "gitlab-token",
                    "target_domain": "gitlab.com",
                    "inject": [
                        { "type": "git_credential", "host": "gitlab.com" },
                        { "type": "env", "var": "GITLAB_TOKEN" }
                    ]
                }
            ]
        }"#,
        )
        .expect("should parse");

        let map = manifest.git_host_map();
        assert_eq!(map.len(), 2, "should have 2 git host mappings");
        assert_eq!(map["github.com"], ("github-pat", "github.com"));
        assert_eq!(map["gitlab.com"], ("gitlab-token", "gitlab.com"));
    }

    #[test]
    fn empty_manifest() {
        let manifest = from_json(r#"{ "credentials": [] }"#).expect("should parse empty manifest");
        assert!(manifest.credentials.is_empty());
        assert!(manifest.git_host_map().is_empty());
    }

    #[test]
    fn invalid_json_errors() {
        assert!(from_json("not json").is_err());
    }

    #[test]
    fn unknown_mechanism_type_errors() {
        let json = r#"{
            "credentials": [{
                "secret_name": "x",
                "target_domain": "x.com",
                "inject": [{ "type": "magic", "wand": "elder" }]
            }]
        }"#;
        assert!(from_json(json).is_err(), "unknown inject type should fail to parse");
    }
}
