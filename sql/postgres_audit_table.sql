-- zerolease audit log table (PostgreSQL)
-- Schema version: 1

CREATE TABLE IF NOT EXISTS audit_events (
    event_id      TEXT PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL,
    event         TEXT NOT NULL,
    agent         TEXT NOT NULL,
    peer_identity TEXT NOT NULL,
    outcome       TEXT NOT NULL,
    secret_name   TEXT,
    lease_id      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent);
CREATE INDEX IF NOT EXISTS idx_audit_secret ON audit_events(secret_name);
CREATE INDEX IF NOT EXISTS idx_audit_lease ON audit_events(lease_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
