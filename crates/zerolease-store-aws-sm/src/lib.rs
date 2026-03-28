//! AWS Secrets Manager-backed [`SecretStore`](zerolease::store::SecretStore)
//! for zerolease.
//!
//! Each zerolease secret maps to one Secrets Manager secret, with the
//! encrypted payload and metadata serialized as a JSON blob. This backend
//! leverages AWS-managed encryption, replication, IAM access control, and
//! CloudTrail audit logging alongside zerolease's own encryption layer
//! (defense in depth).
//!
//! This crate provides only a `SecretStore` implementation — pair it with
//! [`TracingAuditLog`](zerolease::audit::tracing_log::TracingAuditLog) or
//! another `AuditLog` backend.

mod store;

pub use store::AwsSecretsManagerStore;
