//! Shared type definitions for the zerolease credential vault.
//!
//! This crate contains the identity newtypes, lease configuration, and
//! metadata types that are shared between the vault core, provider crate,
//! store backends, and downstream consumers. It has no crypto dependencies.

pub mod audit;
pub mod identity;
pub mod lease;
pub mod store;

pub use audit::RevocationReason;
pub use identity::{AgentId, DomainScope, LeaseId, SecretId, SecretName};
pub use lease::{LeaseGrant, LeaseTerms};
pub use store::{CipherAlgorithm, SecretKind, SecretMetadata};
