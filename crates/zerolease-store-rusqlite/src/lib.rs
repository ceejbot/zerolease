//! Rusqlite-backed storage backends for zerolease.
//!
//! Provides `RusqliteStore` (implements `SecretStore`) and
//! `RusqliteAuditLog` (implements `AuditLog`) using `rusqlite`.
//!
//! Use this crate instead of `zerolease-store-sqlx` when your
//! application already depends on `rusqlite` (e.g., zeroclaw),
//! avoiding `libsqlite3-sys` link conflicts.

mod audit;
mod store;

pub use audit::RusqliteAuditLog;
pub use store::RusqliteStore;
