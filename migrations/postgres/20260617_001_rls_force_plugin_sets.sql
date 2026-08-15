-- Postgres RLS enforcement — Phase 3: plugin_sets.
--
-- `plugin_sets` is org-keyed (like `workspaces`/`instances`): the policy filters
-- on `org_id = current_setting('mcpg.org_id')`. Every code path that reads/writes
-- it is now scoped — the plugin-set CRUD handlers (`require_org`), the bind
-- handler's set lookup, and the config-bundle helpers (org threaded from the
-- gRPC `claims.tenant_id`) use the repo's `*_self_scoped` methods. So it is safe
-- to FORCE.
--
-- Policy change vs init.sql: add a WITH CHECK mirroring the USING clause so
-- INSERT/UPDATE are constrained to the scoped org (the original USING-only
-- policy left writes unconstrained). With no scope set the cast of an empty/NULL
-- GUC fails closed (matches the other org-keyed tables).
--
-- Same enforcement caveat: only ACTIVE under a non-superuser runtime role; the
-- default superuser / sqlite path is unaffected (inert).
--
-- NOTE — `bootstrap_tokens` (the other table the plan grouped into "Phase 3") is
-- intentionally NOT FORCEd here. It is consumed by NONCE at gRPC `Register`
-- (`bootstrap_tokens.consume(nonce, uid)`) with NO org in hand — the nonce is
-- the cross-tenant lookup key and the org is its result (like a session token).
-- That genuinely org-less lookup can't be scoped under the owner role, so
-- `bootstrap_tokens` waits for the end-state BYPASSRLS pool, alongside
-- `org_memberships` (looked up cross-org by user during auth).

ALTER POLICY tenant_iso_plugin_sets ON plugin_sets
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);

ALTER TABLE plugin_sets FORCE ROW LEVEL SECURITY;
