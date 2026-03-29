//! # zerolease
//!
//! A credential vault for AI agent environments. Stores secrets encrypted
//! at rest and grants access through leases: time-bounded, scope-restricted
//! handles that expire automatically and can be revoked at any time.
//!
//! ## Deployment context
//!
//! ```text
//!                 ┌───────────┐
//!                 │   Slack   │
//!                 └─────┬─────┘
//!                       │ message
//!                       ▼
//!  ┌──────────────────────────────────────┐
//!  │         Orchestrator (host)          │
//!  │                                      │
//!  │  ┌──────────┐    ┌───────────────┐   │
//!  │  │ zerolease│◀──▶│ VaultClient   │   │
//!  │  │  server  │    └───────────────┘   │
//!  │  │          │          ▲             │
//!  │  │ UDS/vsock│          │ lease       │
//!  │  └──┬───┬───┘          │             │
//!  │     │   │        ┌─────┴──────┐      │
//!  │     │   │        │  Agent VM  │      │
//!  │     │   │        │ (tool use) │      │
//!  │     │   │        └────────────┘      │
//!  └─────┼───┼────────────────────────────┘
//!        │   │
//!    ┌───┘   └────┐
//!    ▼            ▼
//! ┌────────┐  ┌───────────┐
//! │SQLite  │  │  AWS KMS  │
//! │  or    │  │(envelope  │
//! │Postgres│  │encryption)│
//! └────────┘  └───────────┘
//! ```
//!
//! The vault server runs on the host alongside the orchestrator. Agents
//! inside VMs connect over vsock; local tools connect over Unix domain
//! sockets. The orchestrator authenticates as an Orchestrator role
//! (trusted to assert agent identity per request), while direct agent
//! connections are bound to a single identity at connection time.
//!
//! ## Core concepts
//!
//! - **[`Vault`](vault::Vault)** — the central coordinator. Owns encryption,
//!   storage, policy, and lease tracking. Generic over backend traits.
//! - **[`Lease`](lease::Lease)** — a time-bounded, scope-restricted handle to a
//!   credential. Carries its expiration, allowed domains, and use count. The
//!   [`LeaseGuard`](lease::LeaseGuard) wraps the decrypted value and zeroizes
//!   it on drop.
//! - **[`PolicyEngine`](policy::PolicyEngine)** — deny-by-default access
//!   control. Evaluates whether an agent can access a secret for a given
//!   domain. Simple flat grant list, first match wins.
//! - **[`Authenticator`](auth::Authenticator)** — maps transport-level peer
//!   identity to roles (Admin, Agent, Orchestrator). Pluggable for different
//!   deployment contexts.
//!
//! ## Backend traits
//!
//! The vault is generic over four backend traits, selected at compile time:
//!
//! | Trait | Purpose | Implementations |
//! |-------|---------|-----------------|
//! | [`KeySource`](keysource::KeySource) | DEK management | [`EnvVarSource`](keysource::env::EnvVarSource), [`KeychainSource`](keysource::keychain::KeychainSource), `KmsSource` (feature `kms`) |
//! | [`SecretStore`](store::SecretStore) | Encrypted persistence | [`SqliteStore`](store::sqlite::SqliteStore), `PostgresStore` (feature `postgres`) |
//! | [`AuditLog`](audit::AuditLog) | Event logging | [`SqliteAuditLog`](audit::sqlite::SqliteAuditLog) |
//! | [`VaultListener`](transport::VaultListener) | Accept connections | [`UdsListener`](transport::uds::UdsListener), `VsockListener` (feature `vsock`) |
//!
//! ## Security properties
//!
//! - Secrets are encrypted at rest (AES-256-GCM or XChaCha20-Poly1305)
//! - Secret values implement `Zeroize` and are scrubbed from memory on drop
//! - Decryption intermediaries use `Zeroizing<Vec<u8>>`
//! - Leases enforce domain restrictions, TTLs, use counts, and per-agent caps
//! - DEK rotation is atomic (database transaction)
//! - Admin operations require Admin role; agents cannot self-assert identity
//! - All audit events flow through `tracing` regardless of backend

pub mod audit;
pub mod auth;
pub mod client;
pub mod crypto;
pub mod error;
pub mod keysource;
pub mod lease;
pub mod policy;
pub mod protocol;
pub mod server;
pub mod store;
pub mod transport;
pub mod types {
    pub use zerolease_types::identity::*;
    pub use zerolease_types::lease::{LeaseGrant, LeaseTerms};
    pub use zerolease_types::store::{CipherAlgorithm, SecretKind, SecretMetadata};
    pub use zerolease_types::audit::RevocationReason;
}
pub mod vault;

#[cfg(test)]
mod security_tests;
