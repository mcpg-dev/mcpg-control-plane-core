-- Postgres RLS enforcement — observability vertical (1/3):
-- `instance_status_reports`.
--
-- This table was ENABLE'd (USING-only) in
-- 20260502_001_instance_status_reports.sql but never FORCEd and never scoped
-- by the repo layer — so under the owner-non-superuser runtime role it was
-- bypassed (ENABLE is owner-bypassed). That left it as the last fail-open gap
-- blocking the owner→non-owner role switch: under a non-owner role ENABLE would
-- suddenly enforce and every unscoped read/write would fail closed.
--
-- The repo (apps/control-plane/server/src/repo/instance_status.rs) now scopes:
--   * `insert` (gRPC StatusReport hot path) — self-scopes to the report's org;
--   * `latest_for_instance_self_scoped` / `list_for_instance_self_scoped`
--     (per-instance dashboard reads) — scope to the caller's org;
--   * `prune_older_than` (obs pruner) — self-scopes per org;
--   * `known_orgs` (obs pruner iteration) — runs on the BYPASSRLS bg pool
--     (inherently cross-org: it answers "which orgs have rows?").
--
-- Policy change vs 20260502: standardize the cast to `::UUID` (the init.sql
-- shape) and add a matching WITH CHECK so INSERT/UPDATE are pinned to the
-- scoped org, not just row VISIBILITY. With `mcpg.org_id` unset, a connection
-- that previously carried a scope sees '' so `''::UUID` THROWS (a forgotten
-- scope is a LOUD error); a never-scoped connection sees NULL so the row fails
-- to match (0 rows). Both fail closed — no row leaks. (The original `::text`
-- form fails closed too, but returns 0 rows silently on reuse; aligning to
-- `::UUID` gives every FORCEd table identical fail-closed semantics, which the
-- rls_enforcement.rs tests assert.)
--
-- Enforcement only ACTIVATES under a non-superuser runtime role (superuser
-- bypasses all RLS; owner bypasses ENABLE but is subject to FORCE). See
-- docs/control-plane/POSTGRES.md.

ALTER POLICY tenant_iso_isr ON instance_status_reports
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);

ALTER TABLE instance_status_reports FORCE ROW LEVEL SECURITY;
