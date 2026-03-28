//! Connection authentication and role-based access control.
//!
//! The `Authenticator` trait determines what a connection is allowed to do
//! based on the transport-level `PeerIdentity`. Three roles exist:
//!
//! - **Admin**: full access to all operations (store, delete, list, rotate)
//! - **Agent**: bound to a single agent identity, can only
//!   request/access/revoke leases
//! - **Orchestrator**: trusted to assert agent identity per request (for
//!   systems acting on behalf of multiple users, like the zeroclaw
//!   orchestrator)

use std::collections::HashMap;
use std::sync::RwLock;

use crate::transport::{hash_token, PeerIdentity, TokenHash};
use crate::types::AgentId;

/// The role assigned to an authenticated connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// Full access to all operations.
    Admin,
    /// Bound to a single agent identity. Cannot call admin operations.
    /// The agent field in requests is ignored — the server substitutes
    /// the bound identity.
    Agent,
    /// Trusted to assert any agent identity per request. Cannot call
    /// admin operations. Used by orchestrators that act on behalf of
    /// multiple users (e.g., a Slack bot, CI system).
    Orchestrator,
}

/// The authenticated identity of a connection.
#[derive(Debug, Clone)]
pub struct ConnectionIdentity {
    /// What this connection is allowed to do.
    pub role: Role,
    /// For Agent connections: the bound agent identity.
    /// For Orchestrator/Admin: None.
    pub agent_id: Option<AgentId>,
    /// Human-readable label for audit logs.
    pub label: String,
}

/// Determines the identity and role of a connection.
///
/// Implementations decide how to map transport-level peer identity
/// to application-level roles. This is where deployment-specific
/// authentication logic lives (e.g., checking Tailscale identity,
/// mapping vsock CIDs to agents, validating bearer tokens from VMs).
///
/// The `token` parameter carries the raw token string from the
/// `ClientHello` (TCP transports). UDS/vsock callers pass `None`.
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync + 'static {
    /// Authenticate a connection based on its transport-level identity
    /// and an optional bearer token from the handshake.
    ///
    /// Returns `Some(identity)` to accept the connection with the given
    /// role and identity, or `None` to reject it entirely.
    async fn authenticate(
        &self,
        peer: &PeerIdentity,
        token: Option<&str>,
    ) -> Option<ConnectionIdentity>;
}

/// An authenticator that grants admin access to all connections.
///
/// **For development and testing only.** Ignores the token entirely.
pub struct AllowAllAdmin;

#[async_trait::async_trait]
impl Authenticator for AllowAllAdmin {
    async fn authenticate(
        &self,
        _peer: &PeerIdentity,
        _token: Option<&str>,
    ) -> Option<ConnectionIdentity> {
        Some(ConnectionIdentity {
            role: Role::Admin,
            agent_id: None,
            label: "allow-all-admin".to_string(),
        })
    }
}

/// A reference token-based authenticator.
///
/// Maps pre-registered tokens to [`ConnectionIdentity`] values.
/// Tokens are stored as SHA-256 hashes — the raw token is never
/// retained after registration.
///
/// This is suitable for testing and simple deployments. Production
/// systems (like the Claw) would implement [`Authenticator`] with
/// their own token lifecycle management.
pub struct TokenAuthenticator {
    tokens: RwLock<HashMap<TokenHash, ConnectionIdentity>>,
}

impl TokenAuthenticator {
    /// Create an empty authenticator with no registered tokens.
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Register a token that maps to the given identity.
    ///
    /// The raw token is hashed immediately and not stored.
    pub fn register(&self, token: &str, identity: ConnectionIdentity) {
        let hash = hash_token(token);
        self.tokens
            .write()
            .expect("token lock poisoned")
            .insert(hash, identity);
    }

    /// Revoke a previously registered token. Returns `true` if the
    /// token was found and removed.
    pub fn revoke(&self, token: &str) -> bool {
        let hash = hash_token(token);
        self.tokens
            .write()
            .expect("token lock poisoned")
            .remove(&hash)
            .is_some()
    }
}

impl Default for TokenAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Authenticator for TokenAuthenticator {
    async fn authenticate(
        &self,
        _peer: &PeerIdentity,
        token: Option<&str>,
    ) -> Option<ConnectionIdentity> {
        let raw = token?;
        let hash = hash_token(raw);
        self.tokens
            .read()
            .expect("token lock poisoned")
            .get(&hash)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allow_all_admin_accepts_without_token() {
        let auth = AllowAllAdmin;
        let id = auth.authenticate(&PeerIdentity::Anonymous, None).await;
        assert!(id.is_some(), "AllowAllAdmin should accept any peer");
        assert_eq!(id.as_ref().expect("identity").role, Role::Admin);
    }

    #[tokio::test]
    async fn token_auth_rejects_without_token() {
        let auth = TokenAuthenticator::new();
        let id = auth.authenticate(&PeerIdentity::Anonymous, None).await;
        assert!(id.is_none(), "should reject when no token provided");
    }

    #[tokio::test]
    async fn token_auth_accepts_registered_token() {
        let auth = TokenAuthenticator::new();
        auth.register(
            "secret-token-123",
            ConnectionIdentity {
                role: Role::Agent,
                agent_id: Some(AgentId::new("test-agent")),
                label: "test".to_string(),
            },
        );

        let id = auth
            .authenticate(&PeerIdentity::Anonymous, Some("secret-token-123"))
            .await;
        assert!(id.is_some(), "should accept registered token");
        let id = id.expect("identity");
        assert_eq!(id.role, Role::Agent);
        assert_eq!(
            id.agent_id.as_ref().expect("agent_id").as_str(),
            "test-agent"
        );
    }

    #[tokio::test]
    async fn token_auth_rejects_unknown_token() {
        let auth = TokenAuthenticator::new();
        auth.register(
            "good-token",
            ConnectionIdentity {
                role: Role::Agent,
                agent_id: None,
                label: "test".to_string(),
            },
        );

        let id = auth
            .authenticate(&PeerIdentity::Anonymous, Some("wrong-token"))
            .await;
        assert!(id.is_none(), "should reject unregistered token");
    }

    #[tokio::test]
    async fn token_auth_revoke_then_reject() {
        let auth = TokenAuthenticator::new();
        auth.register(
            "temp-token",
            ConnectionIdentity {
                role: Role::Agent,
                agent_id: None,
                label: "test".to_string(),
            },
        );

        assert!(auth.revoke("temp-token"), "revoke should return true for known token");
        assert!(!auth.revoke("temp-token"), "second revoke should return false");

        let id = auth
            .authenticate(&PeerIdentity::Anonymous, Some("temp-token"))
            .await;
        assert!(id.is_none(), "should reject revoked token");
    }
}
