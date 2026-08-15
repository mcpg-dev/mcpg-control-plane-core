-- Postgres RLS enforcement — Phase 2b: bindings.
--
-- `bindings` isolation is TRANSITIVE (like `environments`): the policy keys off
-- whether the row's `instance_id` is an instance VISIBLE under the current
-- scope. With `instances` already FORCEd (20260615_001), the `SELECT id FROM
-- instances` subquery returns only the scoped org's instances, so `bindings`
-- inherits the org boundary. Both tables must be FORCEd for the chain to be
-- airtight — which, after this migration, they are.
--
-- Policy change vs init.sql: add a WITH CHECK mirroring the USING clause so an
-- INSERT/UPDATE can only bind an instance visible under the current scope. With
-- no scope set the instance subquery is empty, so unscoped reads and writes both
-- fail closed.
--
-- Same enforcement caveat: only ACTIVE under a non-superuser runtime role; the
-- default superuser / sqlite path is unaffected (inert).

ALTER POLICY tenant_iso_bindings ON bindings
    USING (instance_id IN (SELECT id FROM instances))
    WITH CHECK (instance_id IN (SELECT id FROM instances));

ALTER TABLE bindings FORCE ROW LEVEL SECURITY;
