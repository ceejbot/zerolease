//! Audit log implementation that emits events via the `tracing` facade.
//!
//! This is the default audit backend for deployments where audit events
//! should flow to an external log aggregator (stdout → fluentd/vector →
//! ELK/Datadog/CloudWatch Insights). The `record()` method emits a
//! structured `tracing::info!` event; the `query_*()` methods return
//! `Error::NotSupported` because querying happens in the log aggregator,
//! not in zerolease.

use crate::audit::{AuditEntry, AuditLog};
use crate::error::{Error, Result};
use crate::types::{AgentId, LeaseId, SecretName};

/// An audit log that emits events as structured `tracing` spans.
///
/// Pair this with any `SecretStore` backend when you don't need
/// in-process audit querying — your log aggregator handles search.
///
/// ```rust,no_run
/// use zerolease::audit::tracing_log::TracingAuditLog;
///
/// let audit = TracingAuditLog::new();
/// ```
pub struct TracingAuditLog;

impl TracingAuditLog {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TracingAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AuditLog for TracingAuditLog {
    async fn record(&self, entry: AuditEntry) -> Result<()> {
        let (secret_name, lease_id) = entry.event.indexed_fields();
        let lease_id_str = lease_id.map(|id| id.as_uuid().to_string());
        let event_json = serde_json::to_string(&entry.event)
            .map_err(|e| Error::Storage(format!("failed to serialize audit event: {e}")))?;
        let outcome_json = serde_json::to_string(&entry.outcome)
            .map_err(|e| Error::Storage(format!("failed to serialize audit outcome: {e}")))?;

        tracing::info!(
            target: "zerolease::audit",
            event_id = %entry.event_id,
            timestamp = %entry.timestamp,
            agent = %entry.agent.as_str(),
            peer_identity = %entry.peer_identity,
            event = %event_json,
            outcome = %outcome_json,
            secret_name = secret_name.unwrap_or(""),
            lease_id = lease_id_str.as_deref().unwrap_or(""),
            "audit"
        );
        Ok(())
    }

    async fn query_by_agent(&self, _agent: &AgentId, _limit: usize) -> Result<Vec<AuditEntry>> {
        Err(Error::NotSupported(
            "TracingAuditLog does not support querying; use your log aggregator".into(),
        ))
    }

    async fn query_by_secret(&self, _secret: &SecretName, _limit: usize) -> Result<Vec<AuditEntry>> {
        Err(Error::NotSupported(
            "TracingAuditLog does not support querying; use your log aggregator".into(),
        ))
    }

    async fn query_by_lease(&self, _lease: &LeaseId) -> Result<Vec<AuditEntry>> {
        Err(Error::NotSupported(
            "TracingAuditLog does not support querying; use your log aggregator".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, AuditOutcome};
    use crate::transport::PeerIdentity;

    #[tokio::test]
    async fn record_succeeds() {
        let log = TracingAuditLog::new();
        let entry = AuditEntry::new(
            AuditEvent::DekRotated,
            AgentId::new("test-agent"),
            &PeerIdentity::Anonymous,
            AuditOutcome::Success,
        );
        log.record(entry).await.expect("record should succeed");
    }

    #[tokio::test]
    async fn queries_return_not_supported() {
        let log = TracingAuditLog::new();
        let err = log
            .query_by_agent(&AgentId::new("x"), 10)
            .await
            .expect_err("should be NotSupported");
        assert!(err.to_string().contains("not support"), "error was: {err}");
    }
}
