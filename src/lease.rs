//! Lease types: time-bounded, scope-restricted handles to credentials.
//!
//! A `Lease` is the core abstraction in zerolease. Rather than giving an
//! agent direct access to a credential, the vault issues a lease that:
//!
//! - Expires after a configurable TTL
//! - Is restricted to specific target domains
//! - Is tied to a specific agent identity
//! - Can be revoked at any time by the vault
//! - Is logged for audit purposes
//!
//! The `LeaseGuard` wraps the actual secret value and zeroizes it on drop,
//! ensuring that even if an agent holds a reference longer than intended,
//! the memory is scrubbed.

use chrono::{DateTime, TimeDelta, Utc};
use secrecy::{ExposeSecret, SecretString};
pub use zerolease_types::lease::{LeaseGrant, LeaseTerms};

use crate::error::{Error, Result};
use crate::types::{AgentId, DomainScope, LeaseId, SecretName};

/// A live lease granting an agent access to a specific credential.
///
/// This is the server-side record. The agent receives a `LeaseGrant`
/// (the client-facing view) and uses its `LeaseId` to access the secret.
#[derive(Debug)]
pub struct Lease {
    pub id: LeaseId,
    pub agent: AgentId,
    pub secret_name: SecretName,
    pub allowed_domains: Vec<DomainScope>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub renewable: bool,
    pub max_uses: Option<u32>,
    pub use_count: u32,
    pub revoked: bool,
}

impl Lease {
    /// Create a new lease from terms.
    pub fn new(agent: AgentId, secret_name: SecretName, allowed_domains: Vec<DomainScope>, terms: &LeaseTerms) -> Self {
        let now = Utc::now();
        Self {
            id: LeaseId::new(),
            agent,
            secret_name,
            allowed_domains,
            issued_at: now,
            expires_at: now + terms.ttl,
            renewable: terms.renewable,
            max_uses: terms.max_uses,
            use_count: 0,
            revoked: false,
        }
    }

    /// Check whether this lease is still valid for the given domain.
    /// Returns an error describing why if not.
    pub fn validate(&self, target_domain: &str) -> Result<()> {
        if self.revoked {
            return Err(Error::LeaseRevoked(self.id));
        }

        if Utc::now() > self.expires_at {
            return Err(Error::LeaseExpired(self.id));
        }

        if let Some(max) = self.max_uses
            && self.use_count >= max
        {
            return Err(Error::LeaseExpired(self.id));
        }

        if !self.allowed_domains.iter().any(|d| d.matches(target_domain)) {
            return Err(Error::AccessDenied {
                agent: self.agent.clone(),
                secret: self.secret_name.clone(),
                domain: DomainScope::new(target_domain),
            });
        }

        Ok(())
    }

    /// Record a use of this lease. Returns error if the lease is exhausted.
    pub fn record_use(&mut self) -> Result<()> {
        if let Some(max) = self.max_uses
            && self.use_count >= max
        {
            return Err(Error::LeaseExpired(self.id));
        }
        self.use_count += 1;
        Ok(())
    }

    /// Renew the lease for another TTL period. Only works if the lease
    /// was issued with `renewable: true` and hasn't been revoked.
    pub fn renew(&mut self, extension: TimeDelta) -> Result<()> {
        if self.revoked {
            return Err(Error::LeaseRevoked(self.id));
        }
        if !self.renewable {
            return Err(Error::InvalidConfig(format!("lease {} is not renewable", self.id)));
        }
        self.expires_at = Utc::now() + extension;
        Ok(())
    }

    /// Revoke this lease immediately.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Time remaining before expiration.
    pub fn time_remaining(&self) -> TimeDelta {
        self.expires_at - Utc::now()
    }
}

impl From<&Lease> for LeaseGrant {
    fn from(lease: &Lease) -> Self {
        Self {
            lease_id: lease.id,
            secret_name: lease.secret_name.clone(),
            allowed_domains: lease.allowed_domains.clone(),
            expires_at: lease.expires_at,
            renewable: lease.renewable,
            remaining_uses: lease.max_uses.map(|max| max.saturating_sub(lease.use_count)),
        }
    }
}

/// A guard holding a decrypted secret value. Zeroizes on drop.
///
/// This is intentionally NOT Clone, NOT Serialize, and NOT Debug
/// (for the inner value). You can expose the secret for the duration
/// of use, but it cannot be accidentally persisted, logged, or copied.
pub struct LeaseGuard {
    lease_id: LeaseId,
    value: SecretString,
}

impl LeaseGuard {
    pub(crate) fn new(lease_id: LeaseId, value: SecretString) -> Self {
        Self { lease_id, value }
    }

    /// The lease this guard is associated with.
    pub fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    /// Expose the secret value. Use this at the network boundary
    /// when injecting the credential into an HTTP request.
    ///
    /// The returned reference is valid only for the lifetime of the
    /// closure—you cannot store it.
    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R,
    {
        f(self.value.expose_secret())
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        // SecretString already zeroizes on drop via secrecy crate,
        // but we explicitly note the intent here. The inner value
        // will be overwritten with zeros when this guard is dropped.
        tracing::trace!(lease_id = %self.lease_id, "lease guard dropped, secret zeroized");
    }
}

// Prevent accidental debug-printing of secret values.
impl std::fmt::Debug for LeaseGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseGuard")
            .field("lease_id", &self.lease_id)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_expires_after_ttl() {
        let terms = LeaseTerms {
            ttl: TimeDelta::seconds(-1), // already expired
            renewable: false,
            max_uses: None,
        };
        let lease = Lease::new(
            AgentId::new("test"),
            SecretName::new("token"),
            vec![DomainScope::new("api.example.com")],
            &terms,
        );
        assert!(lease.validate("api.example.com").is_err());
    }

    #[test]
    fn lease_domain_restriction() {
        let terms = LeaseTerms::default_short();
        let lease = Lease::new(
            AgentId::new("test"),
            SecretName::new("token"),
            vec![DomainScope::new("api.github.com")],
            &terms,
        );
        assert!(lease.validate("api.github.com").is_ok());
        assert!(lease.validate("evil.example.com").is_err());
    }

    #[test]
    fn single_use_lease_exhausts() {
        let terms = LeaseTerms::single_use();
        let mut lease = Lease::new(
            AgentId::new("test"),
            SecretName::new("token"),
            vec![DomainScope::new("api.example.com")],
            &terms,
        );
        assert!(lease.record_use().is_ok());
        assert!(lease.record_use().is_err());
    }

    #[test]
    fn revoked_lease_rejects() {
        let terms = LeaseTerms::default_short();
        let mut lease = Lease::new(
            AgentId::new("test"),
            SecretName::new("token"),
            vec![DomainScope::new("api.example.com")],
            &terms,
        );
        lease.revoke();
        assert!(lease.validate("api.example.com").is_err());
    }

    #[test]
    fn non_renewable_lease_rejects_renewal() {
        let terms = LeaseTerms::default_short();
        let mut lease = Lease::new(
            AgentId::new("test"),
            SecretName::new("token"),
            vec![DomainScope::new("api.example.com")],
            &terms,
        );
        assert!(lease.renew(TimeDelta::hours(1)).is_err());
    }

    #[test]
    fn lease_guard_debug_redacts_value() {
        let guard = LeaseGuard::new(LeaseId::new(), SecretString::from("super-secret-token"));
        let debug = format!("{:?}", guard);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret-token"));
    }
}
