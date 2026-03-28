//! Error types for the credential provider.
//!
//! These errors intentionally do not expose vault internals.
//! A tool sees "credential unavailable" — never lease IDs,
//! policy details, or encryption errors.

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The requested credential could not be acquired.
    /// This covers policy denial, missing secrets, and vault errors —
    /// intentionally vague to avoid leaking vault internals.
    #[error("credential unavailable: {0}")]
    Unavailable(String),

    /// The provider could not connect to the vault.
    #[error("vault connection failed: {0}")]
    ConnectionFailed(String),

    /// The credential value was not valid UTF-8.
    #[error("credential is not valid UTF-8")]
    InvalidUtf8,
}
