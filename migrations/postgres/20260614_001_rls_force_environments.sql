-- Postgres RLS enforcement — Phase 1b: environments.
--
-- Extends the phased rollout from 20260613_001 (workspaces). `environments` is
-- now reached only through scoped repo paths (`EnvironmentsRepo::*_scoped` +
-- `get_by_slug_self_scoped`), so it is safe to FORCE.
--
-- environments isolation is TRANSITIVE: the policy keys off whether the row's
-- `workspace_id` is a workspace VISIBLE under the current scope, not off
-- `org_id` directly. With `workspaces` already FORCEd (20260613_001), the
-- `SELECT id FROM workspaces` subquery itself returns only the scoped org's
-- workspaces, so `environments` inherits the org boundary. Both tables must be
-- FORCEd for the chain to be airtight — which, after this migration, they are.
--
-- Policy change vs init.sql: add a WITH CHECK mirroring the USING clause so an
-- INSERT/UPDATE can only place an environment into a workspace visible under the
-- current scope (the original USING-only policy constrained visibility but not
-- writes). With no scope set the workspace subquery is empty, so unscoped reads
-- and writes both fail closed.
--
-- Same enforcement caveat as 20260613_001: only ACTIVE under a non-superuser
-- runtime role; the default superuser / sqlite path is unaffected (inert).

ALTER POLICY tenant_iso_environments ON environments
    USING (workspace_id IN (SELECT id FROM workspaces))
    WITH CHECK (workspace_id IN (SELECT id FROM workspaces));

ALTER TABLE environments FORCE ROW LEVEL SECURITY;
