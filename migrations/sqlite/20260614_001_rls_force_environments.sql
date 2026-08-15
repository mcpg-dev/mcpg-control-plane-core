-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Mirrors the Postgres Phase-1b migration (20260614_001_rls_force_environments.sql),
-- which FORCEs RLS on `environments`. On Sqlite tenant isolation stays at the
-- application layer (the explicit `WHERE workspace_id = ?` filters). This file
-- keeps the sqlite/postgres migration sets in lockstep.
SELECT 1;
