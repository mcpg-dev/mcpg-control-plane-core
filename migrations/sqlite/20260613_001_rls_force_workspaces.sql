-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Tier-0 / self-host single-tenant runs on Sqlite, where tenant isolation is
-- enforced at the application layer (`AuthContext::require_org` + the explicit
-- `WHERE org_id = ?` filters). The matching Postgres migration
-- (20260613_001_rls_force_workspaces.sql) FORCEs RLS on `workspaces` only
-- (`environments` stays ENABLE-only until its repo is scoped). This file exists
-- to keep the sqlite/postgres migration sets in lockstep.
SELECT 1;
