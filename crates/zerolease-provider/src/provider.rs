//! The `CredentialProvider` trait: the bridge between AI agent tools
//! and a credential vault.
//!
//! Tools call `provider.acquire()` at execution time to get a
//! `CredentialGuard` — a time-bounded, domain-scoped, zeroize-on-drop
//! handle to a secret. This replaces the static `String` credential
//! fields that tools typically store for their entire process lifetime.

use crate::credential::CredentialGuard;
use crate::error::ProviderError;

/// A request for a credential, describing what the tool needs.
#[derive(Debug, Clone)]
pub struct CredentialRequest {
    /// Which secret to access (e.g., "jira-api-token").
    pub secret_name: String,
    /// The domain this credential will be used against (e.g.,
    /// "mycompany.atlassian.net").
    pub target_domain: String,
    /// Identity of the requesting agent.
    pub agent_id: String,
}

/// A provider that acquires credentials from a vault on behalf of tools.
///
/// Implementations handle the lease lifecycle: request a lease, access
/// the secret, and arrange for revocation when the guard is dropped.
#[async_trait::async_trait]
pub trait CredentialProvider: Send + Sync {
    /// Acquire a credential for the given request.
    ///
    /// Returns a [`CredentialGuard`] that:
    /// - Provides the secret value via `expose()`
    /// - Zeroizes the secret from memory on drop
    /// - Revokes the underlying lease on drop
    async fn acquire(&self, request: CredentialRequest) -> Result<CredentialGuard, ProviderError>;
}
