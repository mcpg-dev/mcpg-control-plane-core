-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Tier-0 / self-host single-tenant runs on Sqlite, where tenant isolation is
-- enforced at the application layer (`AuthContext::require_org` + the explicit
-- `WHERE org_id = ?` filters). The matching Postgres migration
-- (20260622_001_rls_force_tool_invocations.sql) FORCEs RLS on
-- `tool_invocations` and the two `tool_usage_rollups_{hourly,daily}` tables.
-- This file keeps the sqlite/postgres migration sets in lockstep.
SELECT 1;
