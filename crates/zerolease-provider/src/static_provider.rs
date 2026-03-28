//! A static, in-memory `CredentialProvider` for testing and migration.
//!
//! `StaticProvider` holds credentials in a `HashMap` and returns them
//! without contacting a vault. Guards created by this provider have no
//! revocation channel — drop is a no-op beyond zeroization.
//!
//! This serves two purposes:
//! - Testing tools without a running vault
//! - Representing the "current behavior" (static credentials) behind the
//!   `CredentialProvider` trait during incremental migration

use std::collections::HashMap;

use secrecy::SecretString;

use crate::credential::CredentialGuard;
use crate::error::ProviderError;
use crate::provider::{CredentialProvider, CredentialRequest};

/// An in-memory credential provider backed by a `HashMap`.
///
/// Credentials are keyed by `secret_name`. Domain and agent checks
/// are not enforced (this is a test/migration helper, not a vault).
pub struct StaticProvider {
    credentials: HashMap<String, SecretString>,
}

impl StaticProvider {
    /// Create an empty provider.
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    /// Insert a credential. Overwrites any existing value for the key.
    pub fn insert(&mut self, secret_name: impl Into<String>, value: impl Into<String>) {
        self.credentials
            .insert(secret_name.into(), SecretString::from(value.into()));
    }
}

impl Default for StaticProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl CredentialProvider for StaticProvider {
    async fn acquire(&self, request: CredentialRequest) -> Result<CredentialGuard, ProviderError> {
        let secret = self
            .credentials
            .get(&request.secret_name)
            .ok_or_else(|| ProviderError::Unavailable(format!("no such secret: {}", request.secret_name)))?;

        // Clone the secret value into a new guard. StaticProvider guards
        // have no revocation channel — drop just zeroizes.
        use secrecy::ExposeSecret;
        let cloned = SecretString::from(secret.expose_secret().to_string());
        Ok(CredentialGuard::new_static(cloned, request.target_domain))
    }
}
