-- Postgres RLS enforcement — observability vertical (2/3):
-- `tool_invocations` + the two derived rollup tables
-- (`tool_usage_rollups_hourly`, `tool_usage_rollups_daily`).
--
-- All three were ENABLE'd (USING-only) in 20260503_001_tool_invocations.sql
-- but never FORCEd and never scoped — the same fail-open gap as
-- instance_status_reports (see 20260621). `tool_invocations` is the gRPC
-- MetricsReport HOT PATH; the rollups are written by a cross-org background
-- task.
--
-- The repo (apps/control-plane/server/src/repo/tool_invocations.rs) now scopes:
--   * `insert_batch_with_ids_self_scoped` (MetricsReport hot path) — scopes the
--     whole batch to the report's org; WITH CHECK guarantees every row carries
--     that org (a cross-org row in the batch would be rejected, not silently
--     written);
--   * `recent` / `for_instance` / `top_tools` / `timeseries_for_tool`
--     (dashboard + Prometheus reads) — `*_self_scoped` to the caller's org;
--   * `count_calls_in_window` (quota gate, hot path) — self-scopes; reads both
--     the rollup table and the live raw rows under one org scope;
--   * `belongs_to_org` (payload cross-tenant guard) — self-scopes;
--   * `prune_older_than` (obs pruner) — self-scopes per org;
--   * `compute_hourly_rollups` / `compute_daily_rollups` (obs rollup task) and
--     `known_orgs` (pruner iteration) — run on the BYPASSRLS bg pool. The
--     rollup compute is inherently cross-org (one window scan, grouped by org,
--     writing the correct org_id per rollup row); BYPASSRLS is the honest
--     representation of a trusted internal aggregation, and it bypasses the
--     rollup WITH CHECK while still stamping the right org_id.
--
-- Policy change vs 20260503: standardize the cast to `::UUID` and add a
-- matching WITH CHECK on each of the three tables. Cast/fail-closed rationale
-- identical to 20260621.

ALTER POLICY tenant_iso_ti ON tool_invocations
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE tool_invocations FORCE ROW LEVEL SECURITY;

ALTER POLICY tenant_iso_turh ON tool_usage_rollups_hourly
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE tool_usage_rollups_hourly FORCE ROW LEVEL SECURITY;

ALTER POLICY tenant_iso_turd ON tool_usage_rollups_daily
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE tool_usage_rollups_daily FORCE ROW LEVEL SECURITY;
