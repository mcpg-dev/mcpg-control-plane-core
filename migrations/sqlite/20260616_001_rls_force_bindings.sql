-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Mirrors the Postgres Phase-2b migration (20260616_001_rls_force_bindings.sql),
-- which FORCEs RLS on `bindings`. On Sqlite tenant isolation stays at the
-- application layer (the explicit `WHERE instance_id = ?` filters). This file
-- keeps the sqlite/postgres migration sets in lockstep.
SELECT 1;
