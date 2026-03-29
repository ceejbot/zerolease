//! Lease state file: shared between the provisioner (writer) and
//! the proxy (reader).
//!
//! The provisioner writes this file atomically (write to temp + rename)
//! after acquiring all leases. The proxy reads it at startup and
//! watches for changes via polling or inotify.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The complete lease state for this VM's prompt run.
/// Current lease state schema version.
pub const LEASE_STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseState {
    /// Schema version. The proxy rejects files with unknown versions.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Domain → lease info. The proxy checks this on every CONNECT.
    pub leases: HashMap<String, LeaseInfo>,
}

fn default_version() -> u32 {
    LEASE_STATE_VERSION
}

/// Information about a single active lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    /// The vault lease ID (for revocation queries).
    pub lease_id: String,
    /// When this lease expires (UTC).
    pub expires_at: DateTime<Utc>,
}

impl LeaseState {
    pub fn new() -> Self {
        Self {
            version: LEASE_STATE_VERSION,
            leases: HashMap::new(),
        }
    }

    /// Check if a domain has an active (non-expired) lease.
    pub fn is_allowed(&self, domain: &str) -> bool {
        self.leases.get(domain).is_some_and(|info| info.expires_at > Utc::now())
    }

    /// Remove expired leases from the state.
    pub fn prune_expired(&mut self) {
        let now = Utc::now();
        self.leases.retain(|_, info| info.expires_at > now);
    }

    /// Write the lease state to a file atomically (write-to-temp + rename).
    pub fn write_atomic(&self, path: &Path) -> std::io::Result<()> {
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent dir"))?;
        std::fs::create_dir_all(dir)?;

        let temp_path = path.with_extension("tmp");
        let json =
            serde_json::to_string_pretty(self).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&temp_path, json)?;
        std::fs::rename(&temp_path, path)?;
        Ok(())
    }

    /// Read lease state from a file.
    pub fn read_from(path: &Path) -> std::io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        serde_json::from_str(&contents).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

impl Default for LeaseState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn active_lease_is_allowed() {
        let mut state = LeaseState::new();
        state.leases.insert(
            "github.com".to_string(),
            LeaseInfo {
                lease_id: "abc".to_string(),
                expires_at: Utc::now() + Duration::hours(1),
            },
        );
        assert!(state.is_allowed("github.com"), "active lease should be allowed");
        assert!(!state.is_allowed("evil.com"), "unknown domain should be denied");
    }

    #[test]
    fn expired_lease_is_denied() {
        let mut state = LeaseState::new();
        state.leases.insert(
            "github.com".to_string(),
            LeaseInfo {
                lease_id: "abc".to_string(),
                expires_at: Utc::now() - Duration::hours(1),
            },
        );
        assert!(!state.is_allowed("github.com"), "expired lease should be denied");
    }

    #[test]
    fn prune_removes_expired() {
        let mut state = LeaseState::new();
        state.leases.insert(
            "expired.com".to_string(),
            LeaseInfo {
                lease_id: "old".to_string(),
                expires_at: Utc::now() - Duration::hours(1),
            },
        );
        state.leases.insert(
            "active.com".to_string(),
            LeaseInfo {
                lease_id: "new".to_string(),
                expires_at: Utc::now() + Duration::hours(1),
            },
        );

        state.prune_expired();
        assert_eq!(state.leases.len(), 1, "should keep only active lease");
        assert!(state.leases.contains_key("active.com"));
    }

    #[test]
    fn atomic_write_and_read() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let path = dir.path().join("leases.json");

        let mut state = LeaseState::new();
        state.leases.insert(
            "github.com".to_string(),
            LeaseInfo {
                lease_id: "test-lease".to_string(),
                expires_at: Utc::now() + Duration::hours(1),
            },
        );

        state.write_atomic(&path).expect("should write");
        let loaded = LeaseState::read_from(&path).expect("should read");

        assert!(loaded.is_allowed("github.com"), "loaded state should have active lease");
        assert_eq!(loaded.leases["github.com"].lease_id, "test-lease");
    }
}
