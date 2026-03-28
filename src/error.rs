//! Error types for zerolease.
//!
//! A single error enum covers all vault operations. We derive `thiserror`
//! for ergonomic `?` propagation, and we're careful never to include
//! secret material in error messages or Debug output.

use crate::types::{AgentId, DomainScope, LeaseId, SecretName};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // -- Lease errors --
    #[error("lease {0} has expired")]
    LeaseExpired(LeaseId),

    #[error("lease {0} has been revoked")]
    LeaseRevoked(LeaseId),

    #[error("lease {0} not found")]
    LeaseNotFound(LeaseId),

    // -- Policy errors --
    #[error("agent {agent} is not authorized to access secret {secret} for domain {domain}")]
    AccessDenied {
        agent: AgentId,
        secret: SecretName,
        domain: DomainScope,
    },

    #[error("no policy found for agent {0}")]
    NoPolicyForAgent(AgentId),

    // -- Secret errors --
    #[error("secret {0} not found")]
    SecretNotFound(SecretName),

    #[error("secret {0} already exists")]
    SecretAlreadyExists(SecretName),

    // -- Cryptographic errors --
    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("key source unavailable: {0}")]
    KeySourceUnavailable(String),

    // -- Storage errors --
    #[error("storage error: {0}")]
    Storage(String),

    // -- Transport errors --
    #[error("transport error: {0}")]
    Transport(String),

    // -- Configuration errors --
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    // -- Capability errors --
    #[error("operation not supported: {0}")]
    NotSupported(String),

    // -- Remote errors (client-side) --
    #[error("remote error ({code}): {message}")]
    Remote { code: String, message: String },
}

/// Result alias using our error type.
pub type Result<T> = std::result::Result<T, Error>;
