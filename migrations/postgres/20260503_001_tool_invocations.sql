-- See sqlite mirror for full doc.
--
-- Postgres-specific: monthly partitioning on `tool_invocations`
-- is recommended at scale (>10K calls/sec aggregate) but
-- deferred until dual-backend repo dispatch lands. Schema must
-- stay portable to sqlite for now.

CREATE TABLE tool_invocations (
    id              BIGSERIAL PRIMARY KEY,
    org_id          UUID NOT NULL,
    workspace_id    UUID NOT NULL,
    instance_id     UUID NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    binding_id      UUID,
    plugin_id       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms     INTEGER NOT NULL,
    outcome         TEXT NOT NULL,
    error_code      TEXT,
    error_hash      TEXT,
    request_id      TEXT,
    caller_subject  TEXT
);

CREATE INDEX idx_ti_workspace_time
    ON tool_invocations(workspace_id, ingested_at DESC);
CREATE INDEX idx_ti_tool_time
    ON tool_invocations(workspace_id, plugin_id, tool_name, ingested_at DESC);
CREATE INDEX idx_ti_instance_time
    ON tool_invocations(instance_id, ingested_at DESC);
CREATE INDEX idx_ti_outcome_time
    ON tool_invocations(workspace_id, outcome, ingested_at DESC);
CREATE INDEX idx_ti_org_time
    ON tool_invocations(org_id, ingested_at DESC);

ALTER TABLE tool_invocations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_ti ON tool_invocations
    USING (org_id::text = current_setting('mcpg.org_id', true));


CREATE TABLE tool_usage_rollups_hourly (
    org_id          UUID NOT NULL,
    workspace_id    UUID NOT NULL,
    plugin_id       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    calls           BIGINT NOT NULL,
    errors          BIGINT NOT NULL,
    p50_ms          INTEGER NOT NULL,
    p95_ms          INTEGER NOT NULL,
    p99_ms          INTEGER NOT NULL,
    max_ms          INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, plugin_id, tool_name, window_start)
);
CREATE INDEX idx_turh_workspace_time
    ON tool_usage_rollups_hourly(workspace_id, window_start DESC);
CREATE INDEX idx_turh_org_time
    ON tool_usage_rollups_hourly(org_id, window_start DESC);

ALTER TABLE tool_usage_rollups_hourly ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_turh ON tool_usage_rollups_hourly
    USING (org_id::text = current_setting('mcpg.org_id', true));


CREATE TABLE tool_usage_rollups_daily (
    org_id          UUID NOT NULL,
    workspace_id    UUID NOT NULL,
    plugin_id       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    calls           BIGINT NOT NULL,
    errors          BIGINT NOT NULL,
    p50_ms          INTEGER NOT NULL,
    p95_ms          INTEGER NOT NULL,
    p99_ms          INTEGER NOT NULL,
    max_ms          INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, plugin_id, tool_name, window_start)
);
CREATE INDEX idx_turd_workspace_time
    ON tool_usage_rollups_daily(workspace_id, window_start DESC);
CREATE INDEX idx_turd_org_time
    ON tool_usage_rollups_daily(org_id, window_start DESC);

ALTER TABLE tool_usage_rollups_daily ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_turd ON tool_usage_rollups_daily
    USING (org_id::text = current_setting('mcpg.org_id', true));
