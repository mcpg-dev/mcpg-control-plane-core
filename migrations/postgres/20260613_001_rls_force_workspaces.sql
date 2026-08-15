-- Postgres RLS enforcement — Phase 1: workspaces (only).
--
-- Refines the tenant-isolation policy from 20260428_001_init.sql and turns on
-- FORCE for `workspaces`. This is the first vertical of a phased rollout; later
-- phases FORCE additional tables only once every code path that touches them is
-- org-scoped or runs on the bypass (BYPASSRLS) pool, so there is never a broken
-- intermediate state where a non-superuser role silently sees zero rows.
--
-- Scope is deliberately just `workspaces`: it is the only table with a scoped
-- repo path (apps/control-plane/server/src/repo/workspaces.rs `*_scoped`).
-- `environments` (and the rest) keep ENABLE-only / no FORCE until their repos
-- grow scoped methods — see "Phased rollout" in docs/control-plane/POSTGRES.md.
--
-- IMPORTANT — enforcement only ACTIVATES under a non-superuser runtime role:
--   * a SUPERUSER bypasses RLS entirely (even FORCE),
--   * the table OWNER bypasses ENABLE but is subject to FORCE,
--   * a non-owner, non-superuser role is subject to both.
-- The default `postgres://postgres@...` (superuser) connection is therefore
-- UNAFFECTED by this migration — it is the operator's switch to a non-superuser
-- runtime role (the `mcpg_app` role; see docs/control-plane/POSTGRES.md) that
-- turns enforcement on. Role + GRANT provisioning is an operational step (it
-- carries passwords / auth) and is intentionally NOT in this migration.
--
-- Policy change vs init.sql: add a WITH CHECK matching the USING clause, so
-- INSERT/UPDATE are constrained to the scoped org — not just SELECT/UPDATE/
-- DELETE row VISIBILITY (the original USING-only policy let a scoped caller
-- write any org_id). The `::uuid` cast is kept deliberately (matches init.sql):
-- with `mcpg.org_id` unset, a connection that previously carried a scope sees
-- the placeholder reverted to '' so `''::uuid` THROWS (a forgotten scope is a
-- LOUD error); a never-scoped connection sees `current_setting(...,true)` =>
-- NULL so the row simply fails to match (0 rows). Both are fail-closed — no row
-- leaks — and both shapes are asserted in tests (see rls_enforcement.rs for the
-- never-scoped 0-rows shape and the connection-reuse '' cast-error shape, and
-- postgres_dual_backend.rs for the pooled-reuse cast-error shape).
-- (The later observability migrations use `::text` instead; standardizing the
-- cast across all policies is a separate cleanup, not done here.)

ALTER POLICY tenant_iso_workspaces ON workspaces
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);

ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;
