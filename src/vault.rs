//! The Vault: the central coordinator tying together key management,
//! secret storage, policy enforcement, lease tracking, and audit logging.
//!
//! The `Vault` is the only component that touches all subsystems. Agents
//! interact with it through the server and never access the store, keys,
//! or policy engine directly.
//!
//! ## Lease flow (two-step)
//!
//! ```text
//! 1. request_lease(agent, secret, domain)
//!    PolicyEngine.evaluate() → deny? → audit + error
//!    SecretStore.get() → verify secret exists
//!    create Lease (TTL, domain scope, use count)
//!    audit + return LeaseGrant
//!
//! 2. access_secret(lease_id, target_domain)
//!    Lease.validate() → expired/revoked/wrong domain? → error
//!    SecretStore.get() → encrypted blob
//!    Cipher.decrypt(blob, DEK) → Zeroizing<Vec<u8>>
//!    wrap in LeaseGuard (zeroizes on drop)
//!    audit + return LeaseGuard
//! ```

use std::collections::HashMap;

use secrecy::SecretString;
use tokio::sync::RwLock;

use crate::audit::{AuditEntry, AuditEvent, AuditLog, AuditOutcome, RevocationReason};
use crate::crypto::{Cipher, Sealed};
use crate::error::{Error, Result};
use crate::keysource::{DataEncryptionKey, KeySource};
use crate::lease::{Lease, LeaseGrant, LeaseGuard};
use crate::policy::PolicyEngine;
use crate::session::{Session, SessionPolicy};
use crate::store::{CipherAlgorithm, SecretKind, SecretMetadata, SecretStore, StoreSecretParams};
use crate::transport::PeerIdentity;
use crate::types::{AgentId, DomainScope, LeaseId, SecretName, SessionId, SessionToken};

/// The vault server. Owns all subsystems and coordinates operations.
///
/// Generic over the concrete implementations of each subsystem,
/// allowing compile-time selection of backends:
///
/// ```ignore
/// // Developer laptop configuration:
/// Vault<KeychainSource, SqliteStore, FileAuditLog>
///
/// // Firecracker/QEMU configuration:
/// Vault<KmsSource, PostgresStore, CloudWatchAuditLog>
/// ```
pub struct Vault<K, S, A>
where
    K: KeySource,
    S: SecretStore,
    A: AuditLog,
{
    key_source: K,
    store: S,
    audit: A,
    policy: RwLock<PolicyEngine>,
    leases: RwLock<HashMap<LeaseId, Lease>>,
    sessions: RwLock<HashMap<SessionToken, Session>>,
    dek: RwLock<Option<DataEncryptionKey>>,
    cipher: Cipher,
    /// Maximum active leases allowed per agent. Prevents memory
    /// exhaustion from a compromised agent flooding lease requests.
    max_leases_per_agent: usize,
}

impl<K, S, A> Vault<K, S, A>
where
    K: KeySource,
    S: SecretStore,
    A: AuditLog,
{
    /// Create a new vault with the given subsystems.
    /// Call `initialize()` before serving requests.
    /// Default maximum active leases per agent.
    const DEFAULT_MAX_LEASES_PER_AGENT: usize = 100;

    pub fn new(key_source: K, store: S, audit: A, policy: PolicyEngine, default_algorithm: CipherAlgorithm) -> Self {
        Self {
            key_source,
            store,
            audit,
            policy: RwLock::new(policy),
            leases: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            dek: RwLock::new(None),
            cipher: Cipher::new(default_algorithm),
            max_leases_per_agent: Self::DEFAULT_MAX_LEASES_PER_AGENT,
        }
    }

    /// Set the maximum number of active leases allowed per agent.
    pub fn with_max_leases_per_agent(mut self, max: usize) -> Self {
        self.max_leases_per_agent = max;
        self
    }

    /// Initialize the vault: load or create the DEK.
    /// Must be called before any secret operations.
    pub async fn initialize(&self) -> Result<()> {
        let dek = self.key_source.load_or_create_dek().await?;
        tracing::info!(
            key_source = self.key_source.description(),
            "vault initialized, DEK loaded"
        );
        *self.dek.write().await = Some(dek);
        Ok(())
    }

    /// Request a lease for a secret. This is the primary entry point
    /// for agents.
    ///
    /// 1. Checks policy: is this agent allowed to access this secret for this
    ///    domain?
    /// 2. Verifies the secret exists in the store.
    /// 3. Creates a lease with the appropriate terms.
    /// 4. Logs the event.
    /// 5. Returns a `LeaseGrant` (the client-facing lease handle).
    pub async fn request_lease(
        &self,
        agent: &AgentId,
        secret_name: &SecretName,
        domain: &DomainScope,
        peer: &PeerIdentity,
    ) -> Result<LeaseGrant> {
        // 1. Policy check
        let terms = {
            let policy = self.policy.read().await;
            match policy.evaluate(agent, secret_name, domain) {
                Ok(terms) => terms,
                Err(e) => {
                    self.trace_and_record(AuditEntry::new(
                        AuditEvent::AccessDenied {
                            secret_name: secret_name.clone(),
                            requested_domain: domain.clone(),
                            reason: e.to_string(),
                        },
                        agent.clone(),
                        peer,
                        AuditOutcome::Denied { reason: e.to_string() },
                    ))
                    .await?;
                    return Err(e);
                }
            }
        };

        // 2. Check lease cap — prevent memory exhaustion from lease flooding
        {
            let leases = self.leases.read().await;
            let active_count = leases.values().filter(|l| &l.agent == agent && !l.revoked).count();
            if active_count >= self.max_leases_per_agent {
                return Err(Error::InvalidConfig(format!(
                    "agent {} has reached the maximum of {} active leases",
                    agent, self.max_leases_per_agent
                )));
            }
        }

        // 3. Verify the secret exists (don't decrypt yet—we're just issuing a lease,
        //    not returning the secret value).
        let _stored = self.store.get(secret_name).await?;

        // 3. Create the lease
        let lease = Lease::new(agent.clone(), secret_name.clone(), vec![domain.clone()], &terms);
        let grant = LeaseGrant::from(&lease);

        // 4. Audit
        self.trace_and_record(AuditEntry::new(
            AuditEvent::LeaseGranted {
                lease_id: lease.id,
                secret_name: secret_name.clone(),
                domains: vec![domain.clone()],
                ttl_seconds: terms.ttl.num_seconds(),
            },
            agent.clone(),
            peer,
            AuditOutcome::Success,
        ))
        .await?;

        // 5. Store the lease
        self.leases.write().await.insert(lease.id, lease);

        tracing::info!(
            lease_id = %grant.lease_id,
            agent = %agent,
            secret = %secret_name,
            domain = %domain,
            expires_at = %grant.expires_at,
            "lease granted"
        );

        Ok(grant)
    }

    /// Access a secret using a lease. This is where decryption happens.
    ///
    /// The agent presents its LeaseId and the target domain. The vault:
    /// 1. Validates the lease (not expired, not revoked, domain matches).
    /// 2. Decrypts the secret using the DEK.
    /// 3. Returns a `LeaseGuard` that zeroizes the secret on drop.
    /// 4. Logs the access.
    pub async fn access_secret(
        &self,
        lease_id: &LeaseId,
        target_domain: &str,
        peer: &PeerIdentity,
    ) -> Result<LeaseGuard> {
        // 1. Validate and update the lease
        let (agent, secret_name) = {
            let mut leases = self.leases.write().await;
            let lease = leases.get_mut(lease_id).ok_or(Error::LeaseNotFound(*lease_id))?;

            lease.validate(target_domain)?;
            lease.record_use()?;

            (lease.agent.clone(), lease.secret_name.clone())
        };

        // 2. Retrieve and decrypt
        let stored = self.store.get(&secret_name).await?;
        let plaintext = self
            .decrypt(&stored.ciphertext, &stored.nonce, stored.algorithm)
            .await?;

        // 3. Wrap in a guard
        let guard = LeaseGuard::new(*lease_id, SecretString::from(plaintext));

        // 4. Audit
        self.trace_and_record(AuditEntry::new(
            AuditEvent::SecretAccessed {
                lease_id: *lease_id,
                secret_name: secret_name.clone(),
                target_domain: DomainScope::new(target_domain),
            },
            agent,
            peer,
            AuditOutcome::Success,
        ))
        .await?;

        Ok(guard)
    }

    /// Revoke a specific lease immediately.
    pub async fn revoke_lease(&self, lease_id: &LeaseId, reason: RevocationReason, peer: &PeerIdentity) -> Result<()> {
        let agent = {
            let mut leases = self.leases.write().await;
            let lease = leases.get_mut(lease_id).ok_or(Error::LeaseNotFound(*lease_id))?;
            lease.revoke();
            lease.agent.clone()
        };

        self.trace_and_record(AuditEntry::new(
            AuditEvent::LeaseRevoked {
                lease_id: *lease_id,
                reason,
            },
            agent,
            peer,
            AuditOutcome::Success,
        ))
        .await?;

        Ok(())
    }

    /// Revoke all active leases for a specific agent.
    /// Used when an agent is compromised or decommissioned.
    pub async fn revoke_all_for_agent(&self, agent: &AgentId, peer: &PeerIdentity) -> Result<usize> {
        let mut leases = self.leases.write().await;
        let mut count = 0;

        for lease in leases.values_mut() {
            if &lease.agent == agent && !lease.revoked {
                lease.revoke();
                count += 1;

                // Best-effort audit logging for each revocation
                self.trace_and_record_best_effort(AuditEntry::new(
                    AuditEvent::LeaseRevoked {
                        lease_id: lease.id,
                        reason: RevocationReason::AdminRevoked,
                    },
                    agent.clone(),
                    peer,
                    AuditOutcome::Success,
                ))
                .await;
            }
        }

        tracing::warn!(
            agent = %agent,
            revoked_count = count,
            "all leases revoked for agent"
        );

        Ok(count)
    }

    /// Store a new secret in the vault.
    ///
    /// Encrypts the plaintext using the DEK, delegates to the store,
    /// and logs the event. This is an admin operation, not agent-initiated.
    pub async fn store_secret(
        &self,
        name: &SecretName,
        plaintext: &[u8],
        kind: SecretKind,
        description: Option<String>,
        peer: &PeerIdentity,
    ) -> Result<SecretMetadata> {
        let sealed = self.encrypt(plaintext).await?;

        let params = StoreSecretParams {
            name: name.clone(),
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce,
            algorithm: sealed.algorithm,
            kind,
            description,
        };

        let stored = self.store.put(params).await?;

        self.trace_and_record(AuditEntry::new(
            AuditEvent::SecretStored {
                secret_name: name.clone(),
            },
            AgentId::new("admin"),
            peer,
            AuditOutcome::Success,
        ))
        .await?;

        Ok(SecretMetadata::from(&stored))
    }

    /// List all stored secret metadata. Admin operation, no policy check.
    pub async fn list_secrets(&self) -> Result<Vec<SecretMetadata>> {
        self.store.list().await
    }

    /// Renew an active lease, extending its expiration.
    ///
    /// If the lease belongs to a session, the session's
    /// `max_renewals_per_lease` is enforced.
    pub async fn renew_lease(
        &self,
        lease_id: &LeaseId,
        extension_secs: i64,
        peer: &PeerIdentity,
    ) -> Result<LeaseGrant> {
        let (grant, agent) = {
            let mut leases = self.leases.write().await;
            let lease = leases.get_mut(lease_id).ok_or(Error::LeaseNotFound(*lease_id))?;

            if chrono::Utc::now() > lease.expires_at {
                return Err(Error::LeaseExpired(*lease_id));
            }

            const MAX_EXTENSION_SECS: i64 = 86400; // 24 hours
            if extension_secs <= 0 || extension_secs > MAX_EXTENSION_SECS {
                return Err(Error::InvalidConfig(format!(
                    "extension must be between 1 and {MAX_EXTENSION_SECS} seconds, got {extension_secs}"
                )));
            }

            // Enforce max_renewals_per_lease when lease belongs to a session
            if let Some(session_id) = lease.session_id {
                let sessions = self.sessions.read().await;
                if let Some(session) = sessions.values().find(|s| s.id == session_id)
                    && lease.renewal_count >= session.policy.max_renewals_per_lease
                {
                    return Err(Error::RenewalLimitReached(
                        *lease_id,
                        session.policy.max_renewals_per_lease,
                    ));
                }
            }

            lease.renew(chrono::TimeDelta::seconds(extension_secs))?;
            (LeaseGrant::from(&*lease), lease.agent.clone())
        };

        self.trace_and_record(AuditEntry::new(
            AuditEvent::LeaseRenewed {
                lease_id: *lease_id,
                extension_secs,
            },
            agent,
            peer,
            AuditOutcome::Success,
        ))
        .await?;

        Ok(grant)
    }

    /// Delete a secret and revoke all active leases for it.
    pub async fn delete_secret(&self, name: &SecretName, peer: &PeerIdentity) -> Result<()> {
        // Note: audit .await calls happen while holding the lease write lock.
        // This matches the existing revoke_all_for_agent pattern. The lock is
        // released (via the scoped block) before the store.delete() call below.
        {
            let mut leases = self.leases.write().await;
            for lease in leases.values_mut() {
                if lease.secret_name == *name && !lease.revoked {
                    lease.revoke();
                    self.trace_and_record_best_effort(AuditEntry::new(
                        AuditEvent::LeaseRevoked {
                            lease_id: lease.id,
                            reason: RevocationReason::SecretDeleted,
                        },
                        lease.agent.clone(),
                        peer,
                        AuditOutcome::Success,
                    ))
                    .await;
                }
            }
        }

        self.store.delete(name).await?;

        self.trace_and_record(AuditEntry::new(
            AuditEvent::SecretDeleted {
                secret_name: name.clone(),
            },
            AgentId::new("admin"),
            peer,
            AuditOutcome::Success,
        ))
        .await?;

        Ok(())
    }

    /// Rotate the data encryption key.
    ///
    /// Generates a new random DEK, re-encrypts every secret in the store
    /// with the new key, persists the new encrypted DEK via the key source,
    /// and swaps the in-memory DEK. This is a heavyweight operation — it
    /// reads and re-writes every secret in the store.
    ///
    /// Only works with key sources that support rotation (e.g., KMS).
    /// EnvVar and Keychain sources will return an error.
    pub async fn rotate_dek(&self, peer: &PeerIdentity) -> Result<()> {
        // 1. Get the old DEK
        let old_dek = {
            let dek = self.dek.read().await;
            let dek = dek
                .as_ref()
                .ok_or(Error::KeySourceUnavailable("vault not initialized (no DEK)".into()))?;
            // We need the raw bytes to create a new DataEncryptionKey for the old one
            DataEncryptionKey::from_bytes(*dek.as_bytes())
        };

        // 2. Generate a new DEK
        let mut new_key_bytes = zeroize::Zeroizing::new([0u8; 32]);
        aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm::aead::OsRng, new_key_bytes.as_mut());
        let new_dek = DataEncryptionKey::from_bytes(*new_key_bytes);

        // 3. Re-encrypt every secret and collect updates
        let secrets = self.store.list().await?;
        let mut updates = Vec::with_capacity(secrets.len());
        for meta in &secrets {
            let stored = self.store.get(&meta.name).await?;

            // Decrypt with old DEK
            let sealed = Sealed {
                ciphertext: stored.ciphertext,
                nonce: stored.nonce,
                algorithm: stored.algorithm,
            };
            let plaintext = self.cipher.decrypt(&sealed, &old_dek)?;

            // Re-encrypt with new DEK
            let new_sealed = self.cipher.encrypt(&plaintext, &new_dek)?;

            updates.push(crate::store::BatchUpdateItem {
                name: meta.name.clone(),
                ciphertext: new_sealed.ciphertext,
                nonce: new_sealed.nonce,
                algorithm: new_sealed.algorithm,
            });
        }

        // 4. Apply all updates atomically — if this fails, no secrets have been
        //    modified and the old DEK is still valid.
        self.store.batch_update(updates).await?;

        // 5. Persist the new encrypted DEK via the key source
        self.key_source.rotate_dek(&new_dek).await?;

        // 6. Swap the in-memory DEK
        *self.dek.write().await = Some(new_dek);

        // 7. Audit
        self.trace_and_record(AuditEntry::new(
            AuditEvent::DekRotated,
            AgentId::new("admin"),
            peer,
            AuditOutcome::Success,
        ))
        .await?;

        tracing::info!(secrets_rotated = secrets.len(), "DEK rotation complete");

        Ok(())
    }

    /// Garbage-collect expired and revoked leases from memory.
    /// Call this periodically (e.g., every minute).
    pub async fn gc_leases(&self) -> usize {
        let mut leases = self.leases.write().await;
        let before = leases.len();
        leases.retain(|_, lease| !lease.revoked && lease.time_remaining().num_seconds() > 0);
        let removed = before - leases.len();
        if removed > 0 {
            tracing::debug!(removed, remaining = leases.len(), "lease GC complete");
        }
        removed
    }

    // -- Session management --

    /// Create a new session. Returns the opaque token and session ID.
    ///
    /// The token is a random 128-bit handle stored in a `HashMap`.
    /// The caller threads it through tool execution context so that
    /// `request_lease_scoped` can validate session scope.
    pub async fn create_session(
        &self,
        user: &str,
        channel: &str,
        policy: SessionPolicy,
        peer: &PeerIdentity,
    ) -> Result<(SessionToken, SessionId)> {
        let session = Session::new(user, channel, policy);
        let session_id = session.id;
        let duration_secs = session.time_remaining().num_seconds();

        // Generate random token
        let mut bytes = [0u8; 16];
        aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm::aead::OsRng, &mut bytes);
        let token = SessionToken::from_bytes(bytes);

        self.sessions.write().await.insert(token.clone(), session);

        self.trace_and_record(AuditEntry::new(
            AuditEvent::SessionCreated {
                session_id,
                user: user.to_owned(),
                channel: channel.to_owned(),
                duration_secs,
            },
            AgentId::new(user),
            peer,
            AuditOutcome::Success,
        ))
        .await?;

        tracing::info!(
            session_id = %session_id,
            user = user,
            channel = channel,
            "session created"
        );

        Ok((token, session_id))
    }

    /// Validate a session token. Returns a clone of the session if active.
    pub async fn validate_session(&self, token: &SessionToken) -> Result<Session> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(token).ok_or(Error::SessionNotFound)?;

        if session.revoked {
            return Err(Error::SessionRevoked(session.id));
        }
        if session.is_expired() {
            return Err(Error::SessionExpired(session.id));
        }

        Ok(session.clone())
    }

    /// Revoke a session and all its child leases.
    pub async fn revoke_session(&self, token: &SessionToken, peer: &PeerIdentity) -> Result<()> {
        // 1. Mark session revoked and capture its ID
        let session_id = {
            let mut sessions = self.sessions.write().await;
            let session = sessions.get_mut(token).ok_or(Error::SessionNotFound)?;
            session.revoke();
            session.id
        };

        // 2. Revoke all child leases
        let mut leases_revoked = 0u32;
        {
            let mut leases = self.leases.write().await;
            for lease in leases.values_mut() {
                if lease.session_id == Some(session_id) && !lease.revoked {
                    lease.revoke();
                    leases_revoked += 1;

                    self.trace_and_record_best_effort(AuditEntry::new(
                        AuditEvent::LeaseRevoked {
                            lease_id: lease.id,
                            reason: RevocationReason::SessionRevoked,
                        },
                        lease.agent.clone(),
                        peer,
                        AuditOutcome::Success,
                    ))
                    .await;
                }
            }
        }

        // 3. Audit session revocation
        self.trace_and_record(AuditEntry::new(
            AuditEvent::SessionRevoked {
                session_id,
                reason: "explicit revocation".into(),
                leases_revoked,
            },
            AgentId::new("session"),
            peer,
            AuditOutcome::Success,
        ))
        .await?;

        tracing::info!(
            session_id = %session_id,
            leases_revoked = leases_revoked,
            "session revoked"
        );

        Ok(())
    }

    /// Request a lease scoped to a session.
    ///
    /// Validates the session, checks tool-to-secret bindings, enforces
    /// concurrent lease limits, then delegates to the standard lease
    /// creation logic. The resulting lease is linked to the session.
    pub async fn request_lease_scoped(
        &self,
        agent: &AgentId,
        secret_name: &SecretName,
        domain: &DomainScope,
        peer: &PeerIdentity,
        session_token: &SessionToken,
        tool_name: &str,
    ) -> Result<LeaseGrant> {
        // 1. Validate session
        let session_id = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(session_token).ok_or(Error::SessionNotFound)?;

            if session.revoked {
                return Err(Error::SessionRevoked(session.id));
            }
            if session.is_expired() {
                return Err(Error::SessionExpired(session.id));
            }

            // 2. Check tool-to-secret binding
            if let Err(_e) = session.check_tool_binding(tool_name, secret_name, domain) {
                self.trace_and_record_best_effort(AuditEntry::new(
                    AuditEvent::ToolBindingDenied {
                        session_id: session.id,
                        tool_name: tool_name.to_owned(),
                        secret_name: secret_name.clone(),
                        reason: format!(
                            "tool '{}' is not bound to secret '{}' for domain '{}'",
                            tool_name, secret_name, domain
                        ),
                    },
                    agent.clone(),
                    peer,
                    AuditOutcome::Denied {
                        reason: "tool-to-secret binding denied".into(),
                    },
                ))
                .await;
                return Err(Error::AccessDenied {
                    agent: AgentId::new(tool_name),
                    secret: secret_name.clone(),
                    domain: domain.clone(),
                });
            }

            // 3. Check concurrent lease limit
            if session.active_lease_count >= session.policy.max_concurrent_leases {
                return Err(Error::SessionLeaseLimitReached(
                    session.id,
                    session.policy.max_concurrent_leases,
                ));
            }

            session.id
        };

        // 4. Use existing request_lease logic for policy check + lease creation
        let grant = self.request_lease(agent, secret_name, domain, peer).await?;

        // 5. Link lease to session and increment active count
        {
            let mut leases = self.leases.write().await;
            if let Some(lease) = leases.get_mut(&grant.lease_id) {
                lease.session_id = Some(session_id);
            }
        }
        {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(session_token) {
                session.active_lease_count += 1;
            }
        }

        Ok(grant)
    }

    /// Garbage-collect expired sessions from memory.
    /// Call this periodically alongside `gc_leases`.
    pub async fn gc_sessions(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, session| session.is_active());
        let removed = before - sessions.len();
        if removed > 0 {
            tracing::debug!(removed, remaining = sessions.len(), "session GC complete");
        }
        removed
    }

    // -- Internal helpers --

    /// Decrypt a secret using the current DEK.
    async fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], algorithm: CipherAlgorithm) -> Result<String> {
        let dek = self.dek.read().await;
        let dek = dek
            .as_ref()
            .ok_or(Error::KeySourceUnavailable("vault not initialized (no DEK)".into()))?;

        let sealed = Sealed {
            ciphertext: ciphertext.to_vec(),
            nonce: nonce.to_vec(),
            algorithm,
        };
        let mut bytes = self.cipher.decrypt(&sealed, dek)?;
        // Swap out the decrypted bytes. The Zeroizing wrapper zeroizes the
        // (now-empty) buffer on drop. The resulting String is short-lived
        // and immediately wrapped in SecretString by the caller.
        let raw = std::mem::take(&mut *bytes);
        String::from_utf8(raw).map_err(|_| Error::DecryptionFailed)
    }

    /// Emit a structured tracing event and persist an audit entry.
    ///
    /// Every audit event flows through `tracing` regardless of the
    /// `AuditLog` backend, so events are always observable via the
    /// standard Rust tracing subscriber. The `AuditLog` provides
    /// optional persistent, queryable storage.
    async fn trace_and_record(&self, entry: AuditEntry) -> Result<()> {
        tracing::info!(
            event = ?entry.event,
            agent = %entry.agent,
            peer = %entry.peer_identity,
            outcome = ?entry.outcome,
            "audit"
        );
        self.audit.record(entry).await
    }

    /// Like `trace_and_record` but ignores storage errors.
    /// Used for best-effort audit in bulk operations.
    async fn trace_and_record_best_effort(&self, entry: AuditEntry) {
        tracing::info!(
            event = ?entry.event,
            agent = %entry.agent,
            peer = %entry.peer_identity,
            outcome = ?entry.outcome,
            "audit"
        );
        let _ = self.audit.record(entry).await;
    }

    /// Encrypt plaintext using the current DEK and default algorithm.
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Sealed> {
        let dek = self.dek.read().await;
        let dek = dek
            .as_ref()
            .ok_or(Error::KeySourceUnavailable("vault not initialized (no DEK)".into()))?;
        self.cipher.encrypt(plaintext, dek)
    }
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "sqlite")]
    use super::*;
    #[cfg(feature = "sqlite")]
    use crate::audit::*;

    /// A no-op audit log that discards all events. For testing only.
    #[cfg(feature = "sqlite")]
    struct NoopAuditLog;

    #[cfg(feature = "sqlite")]
    #[async_trait::async_trait]
    impl AuditLog for NoopAuditLog {
        async fn record(&self, _entry: AuditEntry) -> Result<()> {
            Ok(())
        }

        async fn query_by_agent(&self, _agent: &AgentId, _limit: usize) -> Result<Vec<AuditEntry>> {
            Ok(vec![])
        }

        async fn query_by_secret(&self, _secret: &SecretName, _limit: usize) -> Result<Vec<AuditEntry>> {
            Ok(vec![])
        }

        async fn query_by_lease(&self, _lease: &LeaseId) -> Result<Vec<AuditEntry>> {
            Ok(vec![])
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn end_to_end_store_lease_access() {
        // Set up env var key
        let key_var = "ZEROLEASE_TEST_VAULT_KEY";
        // SAFETY: tests run single-threaded via --test-threads=1
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(key_var, "ab".repeat(32))
        };

        // Create components
        let key_source = EnvVarSource::new(key_var);
        let tmp = NamedTempFile::new().expect("failed to create temp file for test DB");
        let store = zerolease_store_rusqlite::RusqliteStore::new(tmp.path())
            .await
            .expect("failed to initialize SQLite store");
        let audit = NoopAuditLog;

        let policy = PolicyEngine::new(PolicyConfig {
            default_lease_terms: crate::lease::LeaseTerms::default_short(),
            grants: vec![PolicyGrant {
                agent: AgentPattern::Exact(AgentId::new("test-agent")),
                secret: SecretPattern::Exact(SecretName::new("test-token")),
                allowed_domains: vec![DomainScope::new("api.example.com")],
                lease_terms: None,
            }],
        });

        let vault = Vault::new(key_source, store, audit, policy, CipherAlgorithm::Aes256Gcm);
        vault.initialize().await.expect("vault initialization should succeed");

        // Store a secret
        let peer = PeerIdentity::Anonymous;
        let meta = vault
            .store_secret(
                &SecretName::new("test-token"),
                b"super-secret-api-key",
                SecretKind::ApiKey,
                Some("test token".into()),
                &peer,
            )
            .await
            .expect("store_secret should succeed");

        assert_eq!(meta.name, SecretName::new("test-token"));
        assert_eq!(meta.version, 1);

        // Request a lease
        let grant = vault
            .request_lease(
                &AgentId::new("test-agent"),
                &SecretName::new("test-token"),
                &DomainScope::new("api.example.com"),
                &peer,
            )
            .await
            .expect("request_lease should succeed");

        // Access the secret through the lease
        let guard = vault
            .access_secret(&grant.lease_id, "api.example.com", &peer)
            .await
            .expect("access_secret should succeed");

        // Verify the decrypted value matches the original
        guard.expose(|secret| {
            assert_eq!(secret, "super-secret-api-key");
        });

        // Clean up
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(key_var)
        };
    }
}
