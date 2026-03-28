//! Key source abstraction for master encryption key management.
//!
//! The vault encrypts all secrets at rest. The encryption key itself
//! must come from somewhere trustworthy. This module abstracts over
//! the key source so the same vault logic works with:
//!
//! - **OS keychain**: macOS Keychain, Linux secret-service (GNOME Keyring, KDE
//!   Wallet). Suitable for developer laptops.
//! - **AWS KMS**: Hardware-backed key management. The master key never leaves
//!   the HSM; we use envelope encryption where KMS encrypts/decrypts a local
//!   data encryption key (DEK).
//! - **Environment variable**: For CI/CD or testing. The least secure option
//!   but sometimes necessary.
//!
//! ## Envelope encryption pattern
//!
//! For KMS-backed deployments:
//!
//! 1. Generate a random 256-bit DEK locally.
//! 2. Encrypt the DEK with KMS (produces an encrypted DEK blob).
//! 3. Use the plaintext DEK to encrypt secrets locally (fast, no KMS call per
//!    secret).
//! 4. Store the encrypted DEK blob alongside the secret store.
//! 5. On startup, call KMS to decrypt the DEK blob → get plaintext DEK →
//!    decrypt secrets.
//!
//! This gives us hardware-backed key protection without a KMS round-trip
//! for every secret operation.

use zeroize::Zeroize;

use crate::error::Result;

pub mod env;
#[cfg(unix)]
pub mod keychain;
#[cfg(feature = "kms")]
pub mod kms;

/// A 256-bit data encryption key, zeroized on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DataEncryptionKey {
    bytes: [u8; 32],
}

impl DataEncryptionKey {
    /// Create a DEK from raw bytes. The caller is responsible for
    /// ensuring the source bytes are cryptographically random.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Access the key material. Only call this when you're about to
    /// encrypt or decrypt—don't hold onto the reference.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

// Prevent accidental logging of key material.
impl std::fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataEncryptionKey([REDACTED])")
    }
}

/// Encrypted form of a DEK, safe to persist to disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedDek {
    /// The ciphertext blob (KMS-encrypted or otherwise).
    pub ciphertext: Vec<u8>,
    /// Identifier for the key that was used to encrypt this DEK,
    /// so we know which KMS key / keychain entry to use for decryption.
    pub key_id: String,
}

/// Abstraction over where the master encryption key comes from.
///
/// Implementors handle the specifics of key storage and retrieval.
/// The vault calls `load_or_create_dek` on startup and uses the
/// returned DEK for all encryption operations during its lifetime.
#[async_trait::async_trait]
pub trait KeySource: Send + Sync + 'static {
    /// Load an existing DEK or create a new one if none exists.
    ///
    /// For KMS: decrypts the stored encrypted DEK blob, or generates
    /// a new DEK and encrypts it with KMS if starting fresh.
    ///
    /// For keychain: retrieves the DEK from the OS keychain, or
    /// generates and stores a new one.
    async fn load_or_create_dek(&self) -> Result<DataEncryptionKey>;

    /// Rotate the DEK. Generates a new DEK, re-encrypts all secrets
    /// with the new key, and stores the new encrypted DEK blob.
    ///
    /// This is a heavyweight operation that requires access to the
    /// secret store. The vault orchestrates this, calling the key
    /// source for the new DEK and the store for re-encryption.
    async fn rotate_dek(&self, new_dek: &DataEncryptionKey) -> Result<EncryptedDek>;

    /// A human-readable description of this key source for logging.
    /// Must NOT include any key material.
    fn description(&self) -> &str;
}

/// Configuration for selecting a key source at runtime.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum KeySourceConfig {
    /// OS keychain (macOS Keychain, Linux secret-service).
    #[serde(rename = "keychain")]
    Keychain {
        /// Service name for the keychain entry.
        service: String,
        /// Account/username for the keychain entry.
        account: String,
    },

    /// AWS KMS envelope encryption.
    #[serde(rename = "kms")]
    AwsKms {
        /// The KMS key ARN or alias to use.
        key_id: String,
        /// AWS region.
        region: String,
        /// Path to the encrypted DEK blob file.
        encrypted_dek_path: String,
    },

    /// Environment variable (testing/CI only).
    #[serde(rename = "env")]
    EnvVar {
        /// Name of the environment variable holding the hex-encoded key.
        var_name: String,
    },
}

impl KeySourceConfig {
    /// Create a concrete `KeySource` from this configuration.
    ///
    /// Returns a boxed trait object suitable for passing to `Vault::new`.
    /// Some variants require specific platform support or feature flags:
    /// - `Keychain` requires Unix (macOS or Linux)
    /// - `AwsKms` requires the `kms` feature
    pub async fn build(self) -> Result<Box<dyn KeySource>> {
        match self {
            KeySourceConfig::EnvVar { var_name } => Ok(Box::new(env::EnvVarSource::new(var_name))),

            #[cfg(unix)]
            KeySourceConfig::Keychain { service, account } => {
                Ok(Box::new(keychain::KeychainSource::new(service, account)))
            }

            #[cfg(not(unix))]
            KeySourceConfig::Keychain { .. } => Err(crate::error::Error::InvalidConfig(
                "keychain key source is only available on Unix platforms".into(),
            )),

            #[cfg(feature = "kms")]
            KeySourceConfig::AwsKms {
                key_id,
                region,
                encrypted_dek_path,
            } => {
                let source = kms::KmsSource::new(key_id, region, encrypted_dek_path).await?;
                Ok(Box::new(source))
            }

            #[cfg(not(feature = "kms"))]
            KeySourceConfig::AwsKms { .. } => Err(crate::error::Error::InvalidConfig(
                "KMS key source requires the 'kms' feature to be enabled".into(),
            )),
        }
    }
}
