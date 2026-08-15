-- Reverse-tunnel byte-usage ledger (RFC 0026 Phase C metering). See the
-- postgres mirror for the full rationale. Sqlite has no RLS; tenant isolation
-- stays at the application layer (org-scoped repo queries), matching
-- instance_billing_events.

CREATE TABLE tunnel_billing_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id  TEXT NOT NULL,
    bytes   INTEGER NOT NULL CHECK (bytes >= 0),
    at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_tbe_org_at ON tunnel_billing_events(org_id, at);
