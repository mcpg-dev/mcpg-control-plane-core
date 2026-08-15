-- Per-instance-hour metering ledger. See the postgres mirror for the full
-- rationale. Sqlite has no RLS; tenant isolation stays at the application
-- layer (org-scoped repo queries), matching `instance_logs`.
--
-- `org_id` references ORGS, deliberately NOT instances: billing history must
-- survive instance deletion and the GDPR erase, like `tool_usage_rollups_*`.
-- `instance_id`/`workspace_id` carry no FK so erasing those rows never
-- cascades into the ledger.

CREATE TABLE instance_billing_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id       TEXT NOT NULL REFERENCES orgs(id),
    workspace_id TEXT NOT NULL,
    instance_id  TEXT NOT NULL,
    event        TEXT NOT NULL CHECK (event IN ('started', 'resized', 'stopped')),
    size         TEXT NOT NULL DEFAULT 's',
    replicas     INTEGER NOT NULL DEFAULT 1,
    at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Period aggregation per org; open-interval lookups per instance.
CREATE INDEX idx_ibe_org_at ON instance_billing_events(org_id, at);
CREATE INDEX idx_ibe_instance_at ON instance_billing_events(instance_id, at);
