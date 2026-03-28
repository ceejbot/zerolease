//! Audit logging for all credential access events.
//!
//! Every interaction with the vault that touches credentials—lease
//! creation, secret access, lease revocation, policy evaluation
//! failure—is recorded as a structured audit event.
//!
//! The audit log is append-only and must not be tamperable by agents.
//! It's stored separately from secrets (potentially in a different
//! database or shipped to an external system like Splunk/CloudWatch).
//!
//! ## What we log
//!
//! - **Who**: agent identity (AgentId + transport-level PeerIdentity)
//! - **What**: which secret was accessed (by name, never by value)
//! - **When**: timestamp
//! - **How**: lease ID, terms, transport used
//! - **Outcome**: success or denial reason
//!
//! ## What we never log
//!
//! - Secret values (plaintext or ciphertext)
//! - Encryption keys or key material
//! - Full request/response bodies

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::transport::PeerIdentity;
use crate::types::{AgentId, DomainScope, LeaseId, SecretName};

// Audit log implementations live in separate crates alongside their
// corresponding store backends.

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When this event occurred.
    pub timestamp: DateTime<Utc>,

    /// Unique ID for this audit entry (for deduplication/correlation).
    pub event_id: uuid::Uuid,

    /// The type of event.
    pub event: AuditEvent,

    /// Agent that triggered this event.
    pub agent: AgentId,

    /// Transport-level identity of the peer (CID, UID/PID, etc.).
    /// Serialized as a string for storage.
    pub peer_identity: String,

    /// Whether the operation succeeded.
    pub outcome: AuditOutcome,
}

impl AuditEntry {
    pub fn new(event: AuditEvent, agent: AgentId, peer: &PeerIdentity, outcome: AuditOutcome) -> Self {
        Self {
            timestamp: Utc::now(),
            event_id: uuid::Uuid::now_v7(),
            event,
            agent,
            peer_identity: peer.to_string(),
            outcome,
        }
    }
}

/// The type of auditable event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEvent {
    /// A lease was requested and granted.
    LeaseGranted {
        lease_id: LeaseId,
        secret_name: SecretName,
        domains: Vec<DomainScope>,
        ttl_seconds: i64,
    },

    /// A lease was used to access a secret.
    SecretAccessed {
        lease_id: LeaseId,
        secret_name: SecretName,
        target_domain: DomainScope,
    },

    /// A lease was revoked (by the vault, by admin, or by expiration).
    LeaseRevoked {
        lease_id: LeaseId,
        reason: RevocationReason,
    },

    /// A lease was renewed.
    LeaseRenewed { lease_id: LeaseId, extension_secs: i64 },

    /// An access request was denied by policy.
    AccessDenied {
        secret_name: SecretName,
        requested_domain: DomainScope,
        reason: String,
    },

    /// A new secret was stored in the vault.
    SecretStored { secret_name: SecretName },

    /// A secret was rotated (new version).
    SecretRotated { secret_name: SecretName, new_version: u32 },

    /// A secret was deleted.
    SecretDeleted { secret_name: SecretName },

    /// The DEK was rotated.
    DekRotated,

    /// Policy was reloaded.
    PolicyReloaded { grant_count: usize },
}

impl AuditEvent {
    /// Extract denormalized `secret_name` and `lease_id` for database indexing.
    pub fn indexed_fields(&self) -> (Option<String>, Option<String>) {
        match self {
            Self::LeaseGranted {
                secret_name, lease_id, ..
            } => (
                Some(secret_name.as_str().to_string()),
                Some(lease_id.as_uuid().to_string()),
            ),
            Self::SecretAccessed {
                secret_name, lease_id, ..
            } => (
                Some(secret_name.as_str().to_string()),
                Some(lease_id.as_uuid().to_string()),
            ),
            Self::LeaseRevoked { lease_id, .. } => (None, Some(lease_id.as_uuid().to_string())),
            Self::LeaseRenewed { lease_id, .. } => (None, Some(lease_id.as_uuid().to_string())),
            Self::AccessDenied { secret_name, .. } => (Some(secret_name.as_str().to_string()), None),
            Self::SecretStored { secret_name } => (Some(secret_name.as_str().to_string()), None),
            Self::SecretRotated { secret_name, .. } => (Some(secret_name.as_str().to_string()), None),
            Self::SecretDeleted { secret_name } => (Some(secret_name.as_str().to_string()), None),
            Self::DekRotated | Self::PolicyReloaded { .. } => (None, None),
        }
    }
}

/// Why a lease was revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationReason {
    /// TTL expired naturally.
    Expired,
    /// Explicitly revoked by administrator.
    AdminRevoked,
    /// The associated secret was deleted.
    SecretDeleted,
    /// Use limit reached.
    UseLimitReached,
    /// The vault is shutting down and revoking all leases.
    VaultShutdown,
}

/// Outcome of an audited operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOutcome {
    Success,
    Denied { reason: String },
    Error { message: String },
}

/// Trait for audit log backends.
///
/// Implementations might write to SQLite, PostgreSQL, a file,
/// or ship events to an external system.
#[async_trait::async_trait]
pub trait AuditLog: Send + Sync + 'static {
    /// Record an audit entry. This must not block the main vault
    /// operations—implementations should buffer and flush asynchronously
    /// if writing to a slow backend.
    async fn record(&self, entry: AuditEntry) -> Result<()>;

    /// Query recent audit entries for a specific agent.
    async fn query_by_agent(&self, agent: &AgentId, limit: usize) -> Result<Vec<AuditEntry>>;

    /// Query recent audit entries for a specific secret.
    async fn query_by_secret(&self, secret: &SecretName, limit: usize) -> Result<Vec<AuditEntry>>;

    /// Query recent audit entries for a specific lease.
    async fn query_by_lease(&self, lease: &LeaseId) -> Result<Vec<AuditEntry>>;
}
