-- See sqlite mirror for full doc.
--
-- Postgres-specific notes:
-- - `plugins` and `warnings` are JSONB so the rollup task can
--   `jsonb_array_elements()` over them efficiently.
-- - Daily partitioning on `ingested_at` is recommended at
--   scale (>100 instances × 5min cadence ≈ 30K rows/day) but
--   deferred until we wire the dual-backend repo dispatch —
--   sqlite path doesn't get partitions and the schema must
--   stay portable for now.

CREATE TABLE instance_status_reports (
    id              BIGSERIAL PRIMARY KEY,
    org_id          UUID NOT NULL,
    workspace_id    UUID NOT NULL,
    instance_id     UUID NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    reported_at     TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    config_hash     TEXT,
    cpu_percent     DOUBLE PRECISION,
    memory_rss_bytes BIGINT,
    disk_used_bytes BIGINT,
    open_fds        INTEGER,
    conns_open      INTEGER,
    plugins_json    JSONB NOT NULL DEFAULT '[]'::jsonb,
    warnings_json   JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX idx_isr_instance_time
    ON instance_status_reports(instance_id, ingested_at DESC);
CREATE INDEX idx_isr_workspace_time
    ON instance_status_reports(workspace_id, ingested_at DESC);
CREATE INDEX idx_isr_org_time
    ON instance_status_reports(org_id, ingested_at DESC);

-- RLS posture: this table is per-tenant; reuse the existing
-- `mcpg.org_id` session-var pattern from
-- migrations/postgres/20260428_001_init.sql.
ALTER TABLE instance_status_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_isr ON instance_status_reports
    USING (org_id::text = current_setting('mcpg.org_id', true));
