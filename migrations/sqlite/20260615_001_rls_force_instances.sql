-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Mirrors the Postgres Phase-2 migration (20260615_001_rls_force_instances.sql),
-- which FORCEs RLS on `instances`. On Sqlite tenant isolation stays at the
-- application layer (the explicit `WHERE org_id = ?` filters). This file keeps
-- the sqlite/postgres migration sets in lockstep.
SELECT 1;
