-- Postgres RLS enforcement — end-state: org_memberships.
--
-- `org_memberships` is org-keyed (policy `org_id = current_setting('mcpg.org_id')`).
-- `ensure`/`get` carry the org and self-scope on the main pool; but
-- `list_for_user` is INHERENTLY cross-org (the auth bootstrap asks "which orgs
-- may this user touch?" before any org is known), so it runs on the BYPASSRLS
-- background pool — there is no org to scope it to. That bypass pool is why this
-- table is FORCEd only at the end-state (not in the per-table owner-role
-- rollout): under the owner role with a single pool, `list_for_user` would fail
-- closed. See docs/control-plane/POSTGRES.md ("End-state").
--
-- Policy change vs init.sql: add a WITH CHECK mirroring the USING clause so the
-- `ensure` insert is constrained to the scoped org.
--
-- Same caveat: only ACTIVE under a non-superuser runtime role; default superuser
-- / sqlite is unaffected (inert), and `list_for_user` works there because the
-- (default) bg pool is the same superuser/sqlite connection that bypasses RLS.

ALTER POLICY tenant_iso_org_memberships ON org_memberships
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);

ALTER TABLE org_memberships FORCE ROW LEVEL SECURITY;
