-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Tier-0 / self-host single-tenant runs on Sqlite, where tenant isolation is
-- enforced at the application layer (`AuthContext::require_org` + the explicit
-- `WHERE org_id = ?` filters). The matching Postgres migration
-- (20260621_001_rls_force_instance_status_reports.sql) FORCEs RLS on
-- `instance_status_reports`. This file keeps the sqlite/postgres migration sets
-- in lockstep.
SELECT 1;
