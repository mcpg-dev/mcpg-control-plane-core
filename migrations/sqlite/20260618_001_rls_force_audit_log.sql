-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Mirrors the Postgres Phase-5 migration (20260618_001_rls_force_audit_log.sql),
-- which FORCEs RLS on `audit_log`. On Sqlite tenant isolation stays at the
-- application layer (the explicit `WHERE org_id = ?` filters). This file keeps
-- the sqlite/postgres migration sets in lockstep.
SELECT 1;
