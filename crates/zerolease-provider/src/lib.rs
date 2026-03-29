//! zerolease-provider: a `CredentialProvider` trait for AI agent tools.
//!
//! Instead of storing credentials as static `String` fields for the
//! process lifetime, tools call `provider.acquire()` at execution time
//! and receive a `CredentialGuard` that is time-bounded, domain-scoped,
//! and zeroized on drop.
//!
//! The `ZeroleaseProvider` implementation connects to a zerolease vault
//! server over UDS. Other backends (static config, HashiCorp Vault, etc.)
//! can implement the same trait.

pub mod credential;
pub mod error;
pub mod provider;
pub mod static_provider;
#[cfg(feature = "vault")]
pub mod zerolease_provider;

pub use credential::CredentialGuard;
pub use error::ProviderError;
pub use provider::{CredentialProvider, CredentialRequest};
pub use static_provider::StaticProvider;
// Re-export newtypes from zerolease::types so downstream crates don't need
// a direct dependency on the `zerolease` base crate.
pub use zerolease::types::{AgentId, DomainScope, SecretName};
#[cfg(feature = "vault")]
pub use zerolease_provider::ZeroleaseProvider;
