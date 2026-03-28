//! PostgreSQL-backed audit log.

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use zerolease::audit::{AuditEntry, AuditEvent, AuditLog, AuditOutcome};
use zerolease::error::{Error, Result};
use zerolease::types::{AgentId, LeaseId, SecretName};

/// A persistent audit log backed by PostgreSQL.
pub struct PostgresAuditLog {
    pool: PgPool,
}

impl PostgresAuditLog {
    /// Connect to a PostgreSQL database at the given URL.
    /// Creates the audit_events table and indexes if they don't exist.
    pub async fn new(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(url)
            .await
            .map_err(|e| Error::Storage(format!("failed to open audit database: {e}")))?;

        sqlx::raw_sql(include_str!("../../../sql/postgres_audit_table.sql"))
            .execute(&pool)
            .await
            .map_err(|e| Error::Storage(format!("failed to create audit schema: {e}")))?;

        Ok(Self { pool })
    }
}


fn row_to_audit_entry(row: &sqlx::postgres::PgRow) -> Result<AuditEntry> {
    let event_id_str: String = row.try_get("event_id").map_err(|e| Error::Storage(e.to_string()))?;
    let event_id = Uuid::parse_str(&event_id_str).map_err(|e| Error::Storage(format!("invalid event_id: {e}")))?;

    let timestamp: DateTime<Utc> = row
        .try_get::<DateTime<Utc>, _>("timestamp")
        .map_err(|e| Error::Storage(e.to_string()))?;

    let event_str: String = row.try_get("event").map_err(|e| Error::Storage(e.to_string()))?;
    let event: AuditEvent =
        serde_json::from_str(&event_str).map_err(|e| Error::Storage(format!("invalid event JSON: {e}")))?;

    let agent_str: String = row.try_get("agent").map_err(|e| Error::Storage(e.to_string()))?;
    let peer_identity: String = row.try_get("peer_identity").map_err(|e| Error::Storage(e.to_string()))?;

    let outcome_str: String = row.try_get("outcome").map_err(|e| Error::Storage(e.to_string()))?;
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

#[async_trait::async_trait]
impl AuditLog for PostgresAuditLog {
    async fn record(&self, entry: AuditEntry) -> Result<()> {
        let (secret_name, lease_id) = entry.event.indexed_fields();
        let event_id_str = entry.event_id.to_string();
        let event_str = serde_json::to_string(&entry.event)
            .map_err(|e| Error::Storage(format!("failed to serialize event: {e}")))?;
        let agent_str = entry.agent.as_str().to_string();
        let outcome_str = serde_json::to_string(&entry.outcome)
            .map_err(|e| Error::Storage(format!("failed to serialize outcome: {e}")))?;

        sqlx::query(
            "INSERT INTO audit_events (event_id, timestamp, event, agent, peer_identity, outcome, secret_name, lease_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&event_id_str)
        .bind(entry.timestamp)
        .bind(&event_str)
        .bind(&agent_str)
        .bind(&entry.peer_identity)
        .bind(&outcome_str)
        .bind(&secret_name)
        .bind(&lease_id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("failed to insert audit event: {e}")))?;

        Ok(())
    }

    async fn query_by_agent(&self, agent: &AgentId, limit: usize) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT * FROM audit_events WHERE agent = $1 ORDER BY timestamp DESC LIMIT $2",
        )
        .bind(agent.as_str())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("query_by_agent failed: {e}")))?;

        rows.iter().map(row_to_audit_entry).collect()
    }

    async fn query_by_secret(&self, secret: &SecretName, limit: usize) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT * FROM audit_events WHERE secret_name = $1 ORDER BY timestamp DESC LIMIT $2",
        )
        .bind(secret.as_str())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("query_by_secret failed: {e}")))?;

        rows.iter().map(row_to_audit_entry).collect()
    }

    async fn query_by_lease(&self, lease: &LeaseId) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT * FROM audit_events WHERE lease_id = $1 ORDER BY timestamp DESC",
        )
        .bind(lease.as_uuid().to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("query_by_lease failed: {e}")))?;

        rows.iter().map(row_to_audit_entry).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerolease::audit::AuditOutcome;
    use zerolease::transport::PeerIdentity;
    use zerolease::types::DomainScope;

    fn test_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/zerolease_test".to_string())
    }

    async fn test_audit_log() -> PostgresAuditLog {
        let log = PostgresAuditLog::new(&test_url())
            .await
            .expect("should create audit log");
        sqlx::query("DELETE FROM audit_events")
            .execute(&log.pool)
            .await
            .expect("should clean test data");
        log
    }

    fn make_entry(agent: &str, event: AuditEvent) -> AuditEntry {
        AuditEntry::new(event, AgentId::new(agent), &PeerIdentity::Anonymous, AuditOutcome::Success)
    }

    #[tokio::test]
    #[ignore] // requires running PostgreSQL with zerolease_test database
    async fn record_and_query_by_agent() {
        let log = test_audit_log().await;
        for _ in 0..3 {
            log.record(make_entry("alice", AuditEvent::DekRotated)).await.expect("record");
        }
        log.record(make_entry("bob", AuditEvent::DekRotated)).await.expect("record");

        let results = log.query_by_agent(&AgentId::new("alice"), 10).await.expect("query");
        assert_eq!(results.len(), 3);

        let bob = log.query_by_agent(&AgentId::new("bob"), 10).await.expect("query");
        assert_eq!(bob.len(), 1);
    }

    #[tokio::test]
    #[ignore]
    async fn query_by_secret() {
        let log = test_audit_log().await;
        log.record(make_entry("agent", AuditEvent::LeaseGranted {
            lease_id: LeaseId::new(),
            secret_name: SecretName::new("pg-secret-a"),
            domains: vec![DomainScope::new("api.example.com")],
            ttl_seconds: 900,
        })).await.expect("record");

        let results = log.query_by_secret(&SecretName::new("pg-secret-a"), 10).await.expect("query");
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    #[ignore]
    async fn query_by_lease() {
        let log = test_audit_log().await;
        let lease = LeaseId::new();
        log.record(make_entry("agent", AuditEvent::LeaseGranted {
            lease_id: lease,
            secret_name: SecretName::new("pg-secret"),
            domains: vec![DomainScope::new("example.com")],
            ttl_seconds: 900,
        })).await.expect("record");

        let results = log.query_by_lease(&lease).await.expect("query");
        assert_eq!(results.len(), 1);
    }
}
