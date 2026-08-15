-- Postgres RLS enforcement — Phase 2: instances.
--
-- `instances` is org-keyed (like `workspaces`): the policy filters on
-- `org_id = current_setting('mcpg.org_id')`. Every code path that reads/writes
-- it is now scoped — the HTTP handlers, the providers (kube / self-registration)
-- and the gRPC channel (org from the authenticated `claims.tenant_id`) use the
-- repo's `*_self_scoped` methods, and the two background sweeps (state janitor,
-- credential rotator) scope per-org / per-instance rather than relying on a
-- BYPASSRLS pool. So `instances` is safe to FORCE.
--
-- Policy change vs init.sql: add a WITH CHECK mirroring the USING clause so
-- INSERT/UPDATE are constrained to the scoped org (the original USING-only
-- policy left writes unconstrained). With no scope set the cast of an empty/NULL
-- GUC fails closed (matches `workspaces`).
--
-- Same enforcement caveat: only ACTIVE under a non-superuser runtime role; the
-- default superuser / sqlite path is unaffected (inert).

ALTER POLICY tenant_iso_instances ON instances
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);

ALTER TABLE instances FORCE ROW LEVEL SECURITY;
