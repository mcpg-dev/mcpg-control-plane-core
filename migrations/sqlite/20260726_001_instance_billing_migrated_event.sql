-- Admit `migrated` into the instance-hour ledger. See the postgres mirror for
-- the rationale.
--
-- SQLite cannot alter an inline CHECK, so this is the standard table rebuild
-- (same shape as `20260705_001_orgs_live_slug`): copy into a clone carrying the
-- widened constraint, swap, and recreate the indexes. The migrator wraps this
-- file in one transaction, so a crash mid-swap rolls the whole rebuild back.

CREATE TABLE instance_billing_events_new (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id       TEXT NOT NULL REFERENCES orgs(id),
    workspace_id TEXT NOT NULL,
    instance_id  TEXT NOT NULL,
    event        TEXT NOT NULL CHECK (event IN ('started', 'resized', 'stopped', 'migrated')),
    size         TEXT NOT NULL DEFAULT 's',
    replicas     INTEGER NOT NULL DEFAULT 1,
    at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT INTO instance_billing_events_new
    (id, org_id, workspace_id, instance_id, event, size, replicas, at)
    SELECT id, org_id, workspace_id, instance_id, event, size, replicas, at
    FROM instance_billing_events;
DROP TABLE instance_billing_events;
ALTER TABLE instance_billing_events_new RENAME TO instance_billing_events;

CREATE INDEX idx_ibe_org_at ON instance_billing_events(org_id, at);
CREATE INDEX idx_ibe_instance_at ON instance_billing_events(instance_id, at);
