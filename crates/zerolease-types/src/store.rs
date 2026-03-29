//! Store-related types: cipher algorithms, secret kinds, and metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::identity::{SecretId, SecretName};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherAlgorithm {
    /// AES-256-GCM (hardware-accelerated on x86_64 via AES-NI).
    Aes256Gcm,
    /// XChaCha20-Poly1305 (constant-time, good for non-x86 targets).
    XChaCha20Poly1305,
}

impl CipherAlgorithm {
    /// Plain-string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes256gcm",
            Self::XChaCha20Poly1305 => "xchacha20poly1305",
        }
    }
}

impl std::fmt::Display for CipherAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
    /// Plain-string discriminant for database storage.
    ///
    /// Only the variant name is stored; variant data (e.g., OAuth2's
    /// refresh token fields) lives in the secret blob itself.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pat => "pat",
            Self::OAuth2 { .. } => "oauth2",
            Self::ApiKey => "apikey",
            Self::BasicAuth => "basicauth",
            Self::SshKey => "sshkey",
            Self::ClientCert => "clientcert",
            Self::Opaque => "opaque",
        }
    }
}

impl std::fmt::Display for SecretKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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
