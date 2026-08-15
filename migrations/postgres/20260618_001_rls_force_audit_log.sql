-- Postgres RLS enforcement — Phase 5: audit_log.
--
-- `audit_log` is org-keyed (policy `org_id = current_setting('mcpg.org_id')`).
-- The hash-chain append (`AuditRepo::append`) already runs in a per-org tx (for
-- the `pg_advisory_xact_lock` + atomic chain), and now sets `mcpg.org_id` on that
-- tx; the reads (`verify_chain`, `list_with_filter`/`list_for_org`) open a scoped
-- read-only tx. Every code path carries the org in the entry/args, so the repo
-- self-scopes with no call-site changes. Safe to FORCE.
--
-- Policy change vs init.sql: add a WITH CHECK mirroring the USING clause so an
-- INSERT is constrained to the scoped org (the original USING-only policy left
-- the org_id of an insert unconstrained). With no scope set the cast of an
-- empty/NULL GUC fails closed.
--
-- Same enforcement caveat: only ACTIVE under a non-superuser runtime role; the
-- default superuser / sqlite path is unaffected (inert).

ALTER POLICY tenant_iso_audit_log ON audit_log
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);

ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
