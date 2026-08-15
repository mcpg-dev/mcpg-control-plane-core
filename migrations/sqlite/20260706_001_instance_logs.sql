-- Durable, cross-replica per-instance gateway logs backing `mcpg cloud logs`.
-- See the postgres mirror for the full rationale. Sqlite has no RLS; tenant
-- isolation stays at the application layer (the org-scoped route + the repo's
-- instance-scoped queries), matching the sqlite `instance_status_reports`
-- migration.
--
-- `id` is the monotonic tail/follow cursor (INTEGER PRIMARY KEY AUTOINCREMENT ==
-- rowid, strictly increasing). `at` is the agent emit time (nullable);
-- `ingested_at` is the CP clock used for retention pruning.

CREATE TABLE instance_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id       TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    instance_id  TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    at           TEXT,
    ingested_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    level        INTEGER NOT NULL,
    target       TEXT NOT NULL,
    message      TEXT NOT NULL,
    plugin_id    TEXT NOT NULL DEFAULT ''
);

-- Tail + follow: newest-first / since-cursor scans for one instance.
CREATE INDEX idx_ilog_instance_id ON instance_logs(instance_id, id DESC);

-- Org-scoped pruning + known_orgs iteration.
CREATE INDEX idx_ilog_org_time ON instance_logs(org_id, ingested_at);
