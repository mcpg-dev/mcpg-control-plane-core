-- Persistent storage for `StatusReport` payloads sent by the
-- gateway agent on the Channel stream (RFC 0009 §"StatusReport").
--
-- Pre-M5/Q2-Phase-B these payloads were logged at debug level and
-- dropped — `PluginStatus.invocations`, resource usage curves, and
-- agent warnings were never persisted, so the CP UI couldn't show
-- per-instance health history.
--
-- Schema is intentionally flat: one row per StatusReport ingested.
-- `ingested_at` is the CP-side clock (authoritative for queries
-- to handle agent-side clock drift); `reported_at` is what the
-- agent claimed at emit time.
--
-- Retention is license-driven and pruned by a leader-leased
-- background task — same pattern as the audit ledger.

CREATE TABLE instance_status_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id          TEXT NOT NULL,
    workspace_id    TEXT NOT NULL,
    instance_id     TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    reported_at     TEXT NOT NULL,
    ingested_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    config_hash     TEXT,
    cpu_percent     REAL,
    memory_rss_bytes INTEGER,
    disk_used_bytes INTEGER,
    open_fds        INTEGER,
    conns_open      INTEGER,
    -- Serialised plugin status array — kept as JSON since shape
    -- is deeply nested (id, version, state, error, invocations
    -- per plugin) and we never need to filter on inner fields
    -- in the index. Top-K queries roll up via the workspace
    -- view; raw rows are for drill-down.
    plugins_json    TEXT NOT NULL DEFAULT '[]',
    warnings_json   TEXT NOT NULL DEFAULT '[]'
);

-- Per-instance trail for the detail page.
CREATE INDEX idx_isr_instance_time
    ON instance_status_reports(instance_id, ingested_at DESC);

-- Workspace fleet rollups + tenant-scoped pruning.
CREATE INDEX idx_isr_workspace_time
    ON instance_status_reports(workspace_id, ingested_at DESC);

-- Org-scoped pruning + admin views.
CREATE INDEX idx_isr_org_time
    ON instance_status_reports(org_id, ingested_at DESC);
