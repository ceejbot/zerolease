//! Secret storage backend abstraction.
//!
//! Secrets are stored encrypted at rest. The store never sees plaintext
//! secret values—it receives and returns opaque encrypted blobs. The
//! vault layer handles encryption/decryption using the DEK from the
//! key source.
//!
//! Two backends are planned:
//!
//! - **SQLite**: single-file, zero-config, ideal for developer laptops and
//!   single-host deployments.
//! - **PostgreSQL**: for shared infrastructure where multiple vault instances
//!   need a common secret store, or where you want to leverage existing
//!   database infrastructure, backup tooling, etc.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::types::{SecretId, SecretName};

// Storage backend implementations live in separate crates:
// - zerolease-store-rusqlite (for apps using rusqlite, e.g. zeroclaw)
// - zerolease-store-sqlx (for standalone deployments) [planned]

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

/// Supported AEAD cipher algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherAlgorithm {
    /// AES-256-GCM (hardware-accelerated on x86_64 via AES-NI).
    Aes256Gcm,
    /// XChaCha20-Poly1305 (constant-time, good for non-x86 targets).
    XChaCha20Poly1305,
}

impl CipherAlgorithm {
    /// Serialize to a JSON string for database storage.
    pub fn to_db_string(&self) -> String {
        serde_json::to_string(self).expect("CipherAlgorithm serialization is infallible")
    }

    /// Deserialize from a JSON string read from the database.
    pub fn from_db_string(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| crate::error::Error::Storage(format!("invalid algorithm value: {e}")))
    }
}

/// What kind of credential this is. Informs how it should be injected
/// into requests (e.g., as a Bearer token header vs. basic auth).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretKind {
    /// A personal access token (e.g., GitHub PAT, Jira PAT).
    Pat,
    /// An OAuth2 access token (possibly with a refresh token).
    OAuth2 {
        /// Encrypted refresh token, if available.
        refresh_ciphertext: Option<Vec<u8>>,
        refresh_nonce: Option<Vec<u8>>,
    },
    /// An API key (typically a static string).
    ApiKey,
    /// Username + password pair. The ciphertext contains both,
    /// serialized as a JSON object `{"username": "...", "password": "..."}`.
    BasicAuth,
    /// An SSH private key.
    SshKey,
    /// An mTLS client certificate + private key.
    ClientCert,
    /// Arbitrary secret blob (escape hatch).
    Opaque,
}

impl SecretKind {
    /// Serialize to a JSON string for database storage.
    pub fn to_db_string(&self) -> String {
        serde_json::to_string(self).expect("SecretKind serialization is infallible")
    }

    /// Deserialize from a JSON string read from the database.
    pub fn from_db_string(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| crate::error::Error::Storage(format!("invalid kind value: {e}")))
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

    /// Apply multiple ciphertext updates atomically.
    ///
    /// Either all updates succeed or none do. Used by DEK rotation
    /// to re-encrypt all secrets under a new key without risk of
    /// partial failure leaving mixed encryption states.
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

/// Non-sensitive metadata about a stored secret, returned by `list()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub id: SecretId,
    pub name: SecretName,
    pub kind: SecretKind,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u32,
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
