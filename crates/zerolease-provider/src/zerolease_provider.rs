//! `CredentialProvider` implementation backed by a zerolease vault server.
//!
//! Connects to a vault over UDS, requests leases, and wraps secrets
//! in `CredentialGuard`s that revoke on drop via a background task.

use std::path::{Path, PathBuf};

use secrecy::SecretString;
use tokio::sync::mpsc;
use uuid::Uuid;
use zerolease::audit::RevocationReason;
use zerolease::client::VaultClient;
use zerolease::transport::uds::UdsConnector;

use crate::credential::CredentialGuard;
use crate::error::ProviderError;
use crate::provider::{CredentialProvider, CredentialRequest};

/// A `CredentialProvider` that acquires credentials from a zerolease
/// vault server over a Unix domain socket.
///
/// Each `acquire()` call opens a fresh connection to the vault (fine
/// for a spike; production code would pool connections). A background
/// tokio task handles lease revocation when guards are dropped.
pub struct ZeroleaseProvider {
    socket_path: PathBuf,
    revoke_tx: mpsc::Sender<Uuid>,
}

impl ZeroleaseProvider {
    /// Create a new provider connected to a vault at the given socket path.
    ///
    /// Spawns a background task that revokes leases as `CredentialGuard`s
    /// are dropped.
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        let socket_path = socket_path.as_ref().to_path_buf();
        let (revoke_tx, revoke_rx) = mpsc::channel::<Uuid>(64);

        let bg_socket = socket_path.clone();
        tokio::spawn(revocation_worker(bg_socket, revoke_rx));

        Self { socket_path, revoke_tx }
    }
}

#[async_trait::async_trait]
impl CredentialProvider for ZeroleaseProvider {
    async fn acquire(&self, request: CredentialRequest) -> Result<CredentialGuard, ProviderError> {
        let connector = UdsConnector::new(&self.socket_path);
        let mut client = VaultClient::connect(&connector)
            .await
            .map_err(|e| ProviderError::ConnectionFailed(e.to_string()))?;

        // Request a lease
        let grant = client
            .request_lease(
                request.agent_id.as_str(),
                request.secret_name.as_str(),
                request.target_domain.as_str(),
            )
            .await
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;

        // Access the secret through the lease
        let secret_bytes = client
            .access_secret(*grant.lease_id.as_uuid(), request.target_domain.as_str())
            .await
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;

        let secret_str = String::from_utf8(secret_bytes).map_err(|_| ProviderError::InvalidUtf8)?;

        Ok(CredentialGuard::new(
            SecretString::from(secret_str),
            *grant.lease_id.as_uuid(),
            request.target_domain,
            self.revoke_tx.clone(),
        ))
    }
}

/// Background task that revokes leases as guards are dropped.
///
/// Connects to the vault for each revocation. In production, this
/// would batch revocations or use a persistent connection.
async fn revocation_worker(socket_path: PathBuf, mut rx: mpsc::Receiver<Uuid>) {
    while let Some(lease_id) = rx.recv().await {
        let connector = UdsConnector::new(&socket_path);
        match VaultClient::connect(&connector).await {
            Ok(mut client) => {
                if let Err(e) = client.revoke_lease(lease_id, RevocationReason::AdminRevoked).await {
                    // Best-effort: log and continue. The lease has a TTL
                    // and will expire on its own.
                    tracing::warn!(%lease_id, error = %e, "failed to revoke lease");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not connect for lease revocation");
            }
        }
    }
}
