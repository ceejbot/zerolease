//! SQLite-backed audit log using `rusqlite`.
//!
//! Supports hash-chained entries for offline tamper detection. Each entry
//! includes a SHA-256 hash of the previous entry, forming a chain that
//! can be verified with `verify_audit_chain()`.

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;
use zerolease::audit::{AuditEntry, AuditEvent, AuditLog, AuditOutcome};
use zerolease::error::{Error, Result};
use zerolease::types::{AgentId, LeaseId, SecretName};

/// A persistent audit log backed by SQLite via `rusqlite`.
pub struct RusqliteAuditLog {
    conn: Arc<Mutex<Connection>>,
}

impl RusqliteAuditLog {
    /// Create a new SQLite audit log at the given path.
    /// Uses WAL mode for concurrent read/write performance.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = tokio::task::spawn_blocking(move || {
            let conn =
                Connection::open(&path).map_err(|e| Error::Storage(format!("failed to open audit database: {e}")))?;

            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(|e| Error::Storage(format!("failed to set WAL mode: {e}")))?;

            conn.execute_batch(include_str!("../../../sql/sqlite_audit_table.sql"))
                .map_err(|e| Error::Storage(format!("failed to create audit_events table: {e}")))?;

            // Migrate v1 schema: add hash chain columns if missing
            migrate_add_hash_columns(&conn)?;

            for idx in [
                "CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent)",
                "CREATE INDEX IF NOT EXISTS idx_audit_secret ON audit_events(secret_name)",
                "CREATE INDEX IF NOT EXISTS idx_audit_lease ON audit_events(lease_id)",
                "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)",
            ] {
                conn.execute(idx, [])
                    .map_err(|e| Error::Storage(format!("failed to create index: {e}")))?;
            }

            Ok::<_, Error>(conn)
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))??;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

/// Well-known genesis hash for the first entry in the chain.
const GENESIS_HASH: &str = "sha256:zerolease-audit-genesis";

/// Compute the SHA-256 hash of genesis to seed the chain.
fn genesis_hash() -> String {
    let hash = Sha256::digest(GENESIS_HASH.as_bytes());
    hex::encode(hash)
}

/// Compute the entry hash for an audit entry.
fn compute_entry_hash(
    prev_hash: &str,
    event_id: &str,
    timestamp: &str,
    event_json: &str,
    agent: &str,
    outcome_json: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(event_id.as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(event_json.as_bytes());
    hasher.update(agent.as_bytes());
    hasher.update(outcome_json.as_bytes());
    hex::encode(hasher.finalize())
}

/// Migrate v1 schema to v2 by adding hash chain columns.
fn migrate_add_hash_columns(conn: &Connection) -> Result<()> {
    // Check if prev_hash column already exists
    let has_prev_hash: bool = conn
        .prepare("SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name = 'prev_hash'")
        .and_then(|mut stmt| stmt.query_row([], |row| row.get::<_, i64>(0)))
        .map(|count| count > 0)
        .unwrap_or(false);

    if !has_prev_hash {
        conn.execute_batch(
            "ALTER TABLE audit_events ADD COLUMN prev_hash TEXT;
             ALTER TABLE audit_events ADD COLUMN entry_hash TEXT;",
        )
        .map_err(|e| Error::Storage(format!("failed to add hash chain columns: {e}")))?;
    }
    Ok(())
}

/// Result of verifying the audit hash chain.
#[derive(Debug)]
pub struct AuditChainVerification {
    /// Total entries examined.
    pub total_entries: u64,
    /// Entries whose hash matched the computed value.
    pub verified_entries: u64,
    /// Event ID of the first entry where the chain broke, if any.
    pub first_broken_at: Option<String>,
    /// Whether the entire chain is valid.
    pub is_valid: bool,
}

impl RusqliteAuditLog {
    /// Verify the integrity of the audit hash chain.
    ///
    /// Walks all entries in timestamp order, recomputes each hash, and
    /// compares to the stored value. Returns a summary of the verification.
    ///
    /// This detects offline tampering (editing the SQLite file) but NOT
    /// in-process fabrication (a compromised process can sign fake entries).
    pub async fn verify_audit_chain(&self) -> Result<AuditChainVerification> {
        let conn = Arc::clone(&self.conn);

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn
                .prepare(
                    "SELECT event_id, timestamp, event, agent, outcome, prev_hash, entry_hash
                     FROM audit_events ORDER BY timestamp ASC",
                )
                .map_err(|e| Error::Storage(format!("prepare failed: {e}")))?;

            let mut rows = stmt
                .query([])
                .map_err(|e| Error::Storage(format!("query failed: {e}")))?;

            let mut total = 0u64;
            let mut verified = 0u64;
            let mut first_broken_at: Option<String> = None;
            let mut expected_prev_hash = genesis_hash();

            while let Some(row) = rows.next().map_err(|e| Error::Storage(format!("row next failed: {e}")))? {
                total += 1;

                let event_id: String = row.get("event_id").map_err(|e| Error::Storage(e.to_string()))?;
                let timestamp: String = row.get("timestamp").map_err(|e| Error::Storage(e.to_string()))?;
                let event_json: String = row.get("event").map_err(|e| Error::Storage(e.to_string()))?;
                let agent: String = row.get("agent").map_err(|e| Error::Storage(e.to_string()))?;
                let outcome_json: String = row.get("outcome").map_err(|e| Error::Storage(e.to_string()))?;
                let stored_prev: Option<String> = row.get("prev_hash").map_err(|e| Error::Storage(e.to_string()))?;
                let stored_hash: Option<String> = row.get("entry_hash").map_err(|e| Error::Storage(e.to_string()))?;

                // Entries without hashes (pre-migration) are skipped
                let (Some(stored_prev), Some(stored_hash)) = (stored_prev, stored_hash) else {
                    expected_prev_hash = genesis_hash(); // reset chain after gap
                    continue;
                };

                if stored_prev != expected_prev_hash {
                    if first_broken_at.is_none() {
                        first_broken_at = Some(event_id.clone());
                    }
                } else {
                    let computed =
                        compute_entry_hash(&stored_prev, &event_id, &timestamp, &event_json, &agent, &outcome_json);
                    if computed == stored_hash {
                        verified += 1;
                    } else if first_broken_at.is_none() {
                        first_broken_at = Some(event_id.clone());
                    }
                }

                expected_prev_hash = stored_hash;
            }

            let is_valid = first_broken_at.is_none() && total > 0;
            Ok(AuditChainVerification {
                total_entries: total,
                verified_entries: verified,
                first_broken_at,
                is_valid,
            })
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))?
    }
}

fn row_to_audit_entry(row: &rusqlite::Row<'_>) -> Result<AuditEntry> {
    let event_id_str: String = row.get("event_id").map_err(|e| Error::Storage(e.to_string()))?;
    let event_id = Uuid::parse_str(&event_id_str).map_err(|e| Error::Storage(format!("invalid event_id: {e}")))?;

    let timestamp_str: String = row.get("timestamp").map_err(|e| Error::Storage(e.to_string()))?;
    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
        .map_err(|e| Error::Storage(format!("invalid timestamp: {e}")))?
        .with_timezone(&Utc);

    let event_str: String = row.get("event").map_err(|e| Error::Storage(e.to_string()))?;
    let event: AuditEvent =
        serde_json::from_str(&event_str).map_err(|e| Error::Storage(format!("invalid event JSON: {e}")))?;

    let agent_str: String = row.get("agent").map_err(|e| Error::Storage(e.to_string()))?;
    let peer_identity: String = row.get("peer_identity").map_err(|e| Error::Storage(e.to_string()))?;

    let outcome_str: String = row.get("outcome").map_err(|e| Error::Storage(e.to_string()))?;
    let outcome: AuditOutcome =
        serde_json::from_str(&outcome_str).map_err(|e| Error::Storage(format!("invalid outcome JSON: {e}")))?;

    Ok(AuditEntry {
        event_id,
        timestamp,
        event,
        agent: AgentId::new(agent_str),
        peer_identity,
        outcome,
    })
}

fn query_rows(conn: &Connection, sql: &str, params: &[&dyn rusqlite::types::ToSql]) -> Result<Vec<AuditEntry>> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| Error::Storage(format!("prepare failed: {e}")))?;
    let rows = stmt
        .query_map(params, |row| {
            row_to_audit_entry(row)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
        })
        .map_err(|e| Error::Storage(format!("query failed: {e}")))?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| Error::Storage(format!("row extraction failed: {e}")))?);
    }
    Ok(result)
}

#[async_trait::async_trait]
impl AuditLog for RusqliteAuditLog {
    async fn record(&self, entry: AuditEntry) -> Result<()> {
        let (secret_name, lease_id) = entry.event.indexed_fields();
        let secret_name = secret_name.map(|s| s.to_owned());
        let lease_id = lease_id.map(|id| id.as_uuid().to_string());
        let event_id_str = entry.event_id.to_string();
        let timestamp_str = entry.timestamp.to_rfc3339();
        let event_str = serde_json::to_string(&entry.event)
            .map_err(|e| Error::Storage(format!("failed to serialize event: {e}")))?;
        let agent_str = entry.agent.as_str().to_string();
        let outcome_str = serde_json::to_string(&entry.outcome)
            .map_err(|e| Error::Storage(format!("failed to serialize outcome: {e}")))?;
        let peer = entry.peer_identity;
        let conn = Arc::clone(&self.conn);

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();

            // Fetch the previous entry's hash for the chain
            let prev_hash: String = conn
                .query_row(
                    "SELECT entry_hash FROM audit_events WHERE entry_hash IS NOT NULL ORDER BY timestamp DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_else(|_| genesis_hash());

            let entry_hash = compute_entry_hash(
                &prev_hash,
                &event_id_str,
                &timestamp_str,
                &event_str,
                &agent_str,
                &outcome_str,
            );

            conn.execute(
                "INSERT INTO audit_events (event_id, timestamp, event, agent, peer_identity, outcome, secret_name, lease_id, prev_hash, entry_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![event_id_str, timestamp_str, event_str, agent_str, peer, outcome_str, secret_name, lease_id, prev_hash, entry_hash],
            )
            .map_err(|e| Error::Storage(format!("failed to insert audit event: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))?
    }

    async fn query_by_agent(&self, agent: &AgentId, limit: usize) -> Result<Vec<AuditEntry>> {
        let conn = Arc::clone(&self.conn);
        let agent_str = agent.as_str().to_string();
        let limit = limit as i64;

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            query_rows(
                &conn,
                "SELECT * FROM audit_events WHERE agent = ?1 ORDER BY timestamp DESC LIMIT ?2",
                rusqlite::params![agent_str, limit],
            )
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))?
    }

    async fn query_by_secret(&self, secret: &SecretName, limit: usize) -> Result<Vec<AuditEntry>> {
        let conn = Arc::clone(&self.conn);
        let secret_str = secret.as_str().to_string();
        let limit = limit as i64;

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            query_rows(
                &conn,
                "SELECT * FROM audit_events WHERE secret_name = ?1 ORDER BY timestamp DESC LIMIT ?2",
                rusqlite::params![secret_str, limit],
            )
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))?
    }

    async fn query_by_lease(&self, lease: &LeaseId) -> Result<Vec<AuditEntry>> {
        let conn = Arc::clone(&self.conn);
        let lease_str = lease.as_uuid().to_string();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            query_rows(
                &conn,
                "SELECT * FROM audit_events WHERE lease_id = ?1 ORDER BY timestamp DESC",
                rusqlite::params![lease_str],
            )
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use zerolease::audit::AuditOutcome;
    use zerolease::transport::PeerIdentity;
    use zerolease::types::DomainScope;

    use super::*;

    async fn test_audit_log() -> (RusqliteAuditLog, NamedTempFile) {
        let tmp = NamedTempFile::new().expect("should create temp file");
        let log = RusqliteAuditLog::new(tmp.path())
            .await
            .expect("should create audit log");
        (log, tmp)
    }

    fn make_entry(agent: &str, event: AuditEvent) -> AuditEntry {
        AuditEntry::new(
            event,
            AgentId::new(agent),
            &PeerIdentity::Anonymous,
            AuditOutcome::Success,
        )
    }

    #[tokio::test]
    async fn record_and_query_by_agent() {
        let (log, _tmp) = test_audit_log().await;
        for _ in 0..3 {
            log.record(make_entry("alice", AuditEvent::DekRotated))
                .await
                .expect("record");
        }
        log.record(make_entry("bob", AuditEvent::DekRotated))
            .await
            .expect("record");

        let results = log.query_by_agent(&AgentId::new("alice"), 10).await.expect("query");
        assert_eq!(results.len(), 3);

        let bob = log.query_by_agent(&AgentId::new("bob"), 10).await.expect("query");
        assert_eq!(bob.len(), 1);
    }

    #[tokio::test]
    async fn query_by_secret() {
        let (log, _tmp) = test_audit_log().await;
        log.record(make_entry(
            "agent",
            AuditEvent::LeaseGranted {
                lease_id: LeaseId::new(),
                secret_name: SecretName::new("secret-a"),
                domains: vec![DomainScope::new("api.example.com")],
                ttl_seconds: 900,
            },
        ))
        .await
        .expect("record");

        let results = log
            .query_by_secret(&SecretName::new("secret-a"), 10)
            .await
            .expect("query");
        assert_eq!(results.len(), 1);

        let empty = log.query_by_secret(&SecretName::new("nope"), 10).await.expect("query");
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn query_by_lease() {
        let (log, _tmp) = test_audit_log().await;
        let lease = LeaseId::new();
        log.record(make_entry(
            "agent",
            AuditEvent::LeaseGranted {
                lease_id: lease,
                secret_name: SecretName::new("secret"),
                domains: vec![DomainScope::new("example.com")],
                ttl_seconds: 900,
            },
        ))
        .await
        .expect("record");

        let results = log.query_by_lease(&lease).await.expect("query");
        assert_eq!(results.len(), 1);
    }
}
