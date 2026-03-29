//! Secret storage backend abstraction.
//!
//! Secrets are stored encrypted at rest. The store never sees plaintext
//! secret values—it receives and returns opaque encrypted blobs. The
//! vault layer handles encryption/decryption using the DEK from the
//! key source.
//!
//! Backend implementations live in separate crates:
//!
//! - **zerolease-store-rusqlite**: single-file, zero-config, ideal for
//!   developer laptops, single-host deployments, and apps already using
//!   rusqlite (e.g. zeroclaw).
//! - **zerolease-store-postgres**: for shared infrastructure where multiple
//!   vault instances need a common secret store.
//! - **zerolease-store-aws-sm**: cloud-native storage using AWS Secrets Manager
//!   with IAM access control and CloudTrail audit logging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
pub use zerolease_types::store::{CipherAlgorithm, SecretKind, SecretMetadata};

use crate::error::Result;
use crate::types::{SecretId, SecretName};

// Storage backend implementations live in separate crates.
// See zerolease-store-rusqlite, zerolease-store-postgres, and
// zerolease-store-aws-sm.

/// An encrypted secret as stored in the backend.
///
/// The `ciphertext` field is the AEAD-encrypted secret value.
/// The `nonce` is stored alongside it (AEAD nonces are not secret,
/// but must be unique per encryption operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSecret {
    pub id: SecretId,
    pub name: SecretName,

    /// AEAD-encrypted secret value.
    pub ciphertext: Vec<u8>,

    /// Nonce used for this encryption (12 bytes for AES-GCM,
    /// 24 bytes for XChaCha20-Poly1305).
    pub nonce: Vec<u8>,

    /// Which cipher was used. Allows migrating between algorithms.
    pub algorithm: CipherAlgorithm,

    /// Metadata: what kind of credential this is.
    pub kind: SecretKind,

    /// Optional description (not encrypted—don't put secrets here).
    pub description: Option<String>,

    /// When this secret was first stored.
    pub created_at: DateTime<Utc>,

    /// When this secret was last updated (rotated).
    pub updated_at: DateTime<Utc>,

    /// Version counter, incremented on each rotation.
    pub version: u32,
}

/// Parse a [`CipherAlgorithm`] from a database string.
///
/// Accepts the canonical lowercase forms (`"aes256gcm"`, `"xchacha20poly1305"`)
/// as well as legacy JSON-quoted PascalCase values for backward compatibility.
pub fn parse_cipher_algorithm(s: &str) -> Result<CipherAlgorithm> {
    match s {
        "aes256gcm" => Ok(CipherAlgorithm::Aes256Gcm),
        "xchacha20poly1305" => Ok(CipherAlgorithm::XChaCha20Poly1305),
        // Accept legacy JSON-quoted values for backward compatibility.
        "\"Aes256Gcm\"" => Ok(CipherAlgorithm::Aes256Gcm),
        "\"XChaCha20Poly1305\"" => Ok(CipherAlgorithm::XChaCha20Poly1305),
        other => Err(crate::error::Error::Storage(format!("unknown algorithm: {other}"))),
    }
}

/// Parse a [`SecretKind`] from a database string.
///
/// Returns the variant with default (empty) inner fields — callers
/// populate variant data separately.
pub fn parse_secret_kind(s: &str) -> Result<SecretKind> {
    match s {
        "pat" => Ok(SecretKind::Pat),
        "oauth2" => Ok(SecretKind::OAuth2 {
            refresh_ciphertext: None,
            refresh_nonce: None,
        }),
        "apikey" => Ok(SecretKind::ApiKey),
        "basicauth" => Ok(SecretKind::BasicAuth),
        "sshkey" => Ok(SecretKind::SshKey),
        "clientcert" => Ok(SecretKind::ClientCert),
        "opaque" => Ok(SecretKind::Opaque),
        // Accept legacy JSON-quoted values for backward compatibility.
        other if other.starts_with('"') => {
            let unquoted = other.trim_matches('"');
            // Legacy format used PascalCase variant names.
            match unquoted {
                "Pat" => Ok(SecretKind::Pat),
                "ApiKey" => Ok(SecretKind::ApiKey),
                "BasicAuth" => Ok(SecretKind::BasicAuth),
                "SshKey" => Ok(SecretKind::SshKey),
                "ClientCert" => Ok(SecretKind::ClientCert),
                "Opaque" => Ok(SecretKind::Opaque),
                _ => Err(crate::error::Error::Storage(format!("unknown kind: {other}"))),
            }
        }
        other => Err(crate::error::Error::Storage(format!("unknown kind: {other}"))),
    }
}

/// Parameters for storing a new secret. The vault encrypts the plaintext
/// value before passing it to the store.
#[derive(Debug)]
pub struct StoreSecretParams {
    pub name: SecretName,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: CipherAlgorithm,
    pub kind: SecretKind,
    pub description: Option<String>,
}

/// Storage backend trait.
///
/// All operations are async to support both SQLite (via sqlx's async
/// SQLite driver) and PostgreSQL.
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync + 'static {
    /// Store a new encrypted secret. Returns error if a secret with
    /// the same name already exists.
    async fn put(&self, params: StoreSecretParams) -> Result<StoredSecret>;

    /// Retrieve an encrypted secret by name.
    async fn get(&self, name: &SecretName) -> Result<StoredSecret>;

    /// Update an existing secret's ciphertext (rotation).
    /// Increments the version counter.
    async fn update(
        &self,
        name: &SecretName,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        algorithm: CipherAlgorithm,
    ) -> Result<StoredSecret>;

    /// Apply multiple ciphertext updates in a single operation.
    ///
    /// Used by DEK rotation to re-encrypt all secrets under a new key.
    /// Implementations should provide atomicity where the backend
    /// supports it (e.g. SQL transactions). Backends without native
    /// transaction support (e.g. AWS Secrets Manager) should document
    /// their partial-failure behavior.
    async fn batch_update(&self, updates: Vec<BatchUpdateItem>) -> Result<()>;

    /// Delete a secret by name. Also revokes all active leases for
    /// this secret (the vault layer handles lease revocation).
    async fn delete(&self, name: &SecretName) -> Result<()>;

    /// List all secret names and metadata (never ciphertext).
    async fn list(&self) -> Result<Vec<SecretMetadata>>;
}

/// A single item in a batch update operation.
#[derive(Debug)]
pub struct BatchUpdateItem {
    pub name: SecretName,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: CipherAlgorithm,
}

impl From<&StoredSecret> for SecretMetadata {
    fn from(s: &StoredSecret) -> Self {
        Self {
            id: s.id,
            name: s.name.clone(),
            kind: s.kind.clone(),
            description: s.description.clone(),
            created_at: s.created_at,
            updated_at: s.updated_at,
            version: s.version,
        }
    }
}
