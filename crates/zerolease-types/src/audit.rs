//! Audit-related types.

use serde::{Deserialize, Serialize};

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
