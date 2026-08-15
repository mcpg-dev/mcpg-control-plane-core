-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Mirrors the Postgres end-state migration 20260619_001_rls_force_org_memberships.sql,
-- which FORCEs RLS on `org_memberships`. On Sqlite tenant isolation stays at the
-- application layer (the explicit `WHERE org_id = ?` / `user_id = ?` filters).
-- This file keeps the sqlite/postgres migration sets in lockstep.
SELECT 1;
