-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Mirrors the Postgres end-state migration 20260620_001_rls_force_bootstrap_tokens.sql,
-- which FORCEs RLS on `bootstrap_tokens`. On Sqlite tenant isolation stays at the
-- application layer (the explicit `WHERE org_id = ?` filters). This file keeps
-- the sqlite/postgres migration sets in lockstep.
SELECT 1;
