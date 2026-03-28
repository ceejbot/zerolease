//! SQLite-backed audit log using `rusqlite`.

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use rusqlite::Connection;
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
            conn.execute(
                "INSERT INTO audit_events (event_id, timestamp, event, agent, peer_identity, outcome, secret_name, lease_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![event_id_str, timestamp_str, event_str, agent_str, peer, outcome_str, secret_name, lease_id],
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
