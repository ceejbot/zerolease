//! Credential guard: a zeroize-on-drop, revoke-on-drop handle to a secret.
//!
//! `CredentialGuard` wraps a `SecretString` obtained through a zerolease
//! lease. When the guard is dropped, the secret is zeroized from memory
//! and the lease revocation is requested via a background channel.
//!
//! The `expose()` closure pattern prevents callers from storing the
//! credential in a variable that outlives the guard.

use secrecy::{ExposeSecret, SecretString};
use tokio::sync::mpsc;
use uuid::Uuid;

/// A handle to an active credential. The secret value is accessible
/// only through [`expose()`](Self::expose) and is zeroized when this
/// guard drops. The underlying lease is revoked on drop.
///
/// NOT Clone, NOT Serialize. Debug redacts the secret value.
pub struct CredentialGuard {
    secret: SecretString,
    lease_id: Uuid,
    target_domain: String,
    revoke_tx: Option<mpsc::Sender<Uuid>>,
}

impl CredentialGuard {
    /// Create a guard backed by a vault lease with a revocation channel.
    pub(crate) fn new(
        secret: SecretString,
        lease_id: Uuid,
        target_domain: String,
        revoke_tx: mpsc::Sender<Uuid>,
    ) -> Self {
        Self {
            secret,
            lease_id,
            target_domain,
            revoke_tx: Some(revoke_tx),
        }
    }

    /// Create a guard with no revocation channel (for static/test providers).
    pub(crate) fn new_static(secret: SecretString, target_domain: String) -> Self {
        Self {
            secret,
            lease_id: Uuid::now_v7(),
            target_domain,
            revoke_tx: None,
        }
    }

    /// Access the secret value. The closure receives a `&str` that
    /// must not be stored beyond the closure's scope.
    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R,
    {
        f(self.secret.expose_secret())
    }

    /// The domain this credential is scoped to.
    pub fn target_domain(&self) -> &str {
        &self.target_domain
    }

    /// The lease ID backing this credential.
    pub fn lease_id(&self) -> Uuid {
        self.lease_id
    }
}

impl std::fmt::Debug for CredentialGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialGuard")
            .field("lease_id", &self.lease_id)
            .field("target_domain", &self.target_domain)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CredentialGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.revoke_tx.take() {
            // Best-effort: if the channel is full or closed, we can't
            // block in Drop. The lease will expire on its own via TTL.
            let _ = tx.try_send(self.lease_id);
        }
        // SecretString handles zeroization of the secret value.
    }
}
