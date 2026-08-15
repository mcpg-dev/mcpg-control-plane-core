-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Mirrors the Postgres Phase-3 migration (20260617_001_rls_force_plugin_sets.sql),
-- which FORCEs RLS on `plugin_sets`. On Sqlite tenant isolation stays at the
-- application layer (the explicit `WHERE workspace_id = ?` filters). This file
-- keeps the sqlite/postgres migration sets in lockstep.
SELECT 1;
