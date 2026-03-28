//! PostgreSQL-backed storage backends for zerolease.
//!
//! Provides `PostgresStore` (implements `SecretStore`) and
//! `PostgresAuditLog` (implements `AuditLog`) using `sqlx` with
//! the `postgres` feature.
//!
//! Suitable for shared infrastructure where multiple vault instances
//! need a common store, or where you want to leverage existing
//! PostgreSQL infrastructure and backup tooling.

mod audit;
mod store;

pub use audit::PostgresAuditLog;
pub use store::PostgresStore;
