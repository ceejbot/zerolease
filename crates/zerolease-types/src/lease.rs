//! Lease configuration and grant types.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::identity::{DomainScope, LeaseId, SecretName};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseTerms {
    /// Maximum duration the lease is valid for.
    pub ttl: TimeDelta,

    /// Whether the lease can be renewed before expiration.
    pub renewable: bool,

    /// Maximum number of times the secret can be accessed through
    /// this lease. `None` means unlimited within the TTL.
    pub max_uses: Option<u32>,
}

impl LeaseTerms {
    /// Sensible default: 15 minutes, non-renewable, unlimited uses.
    /// Short enough to limit blast radius, long enough for most
    /// tool invocations.
    pub fn default_short() -> Self {
        Self {
            ttl: TimeDelta::minutes(15),
            renewable: false,
            max_uses: None,
        }
    }

    /// For long-running workflows: 1 hour, renewable.
    pub fn workflow() -> Self {
        Self {
            ttl: TimeDelta::hours(1),
            renewable: true,
            max_uses: None,
        }
    }

    /// Single-use: the tightest possible lease. The credential can be
    /// accessed exactly once, and the lease expires after 5 minutes
    /// regardless.
    pub fn single_use() -> Self {
        Self {
            ttl: TimeDelta::minutes(5),
            renewable: false,
            max_uses: Some(1),
        }
    }
}

/// The client-facing view of a granted lease. This is what the agent
/// receives—it contains the lease ID and metadata but NOT the secret
/// value itself. The agent must present the LeaseId (and a target domain)
/// to retrieve the actual credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseGrant {
    pub lease_id: LeaseId,
    pub secret_name: SecretName,
    pub allowed_domains: Vec<DomainScope>,
    pub expires_at: DateTime<Utc>,
    pub renewable: bool,
    pub remaining_uses: Option<u32>,
}
